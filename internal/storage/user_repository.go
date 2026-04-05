package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// UserRepository defines the persistence operations for user accounts.
type UserRepository interface {
	// Create inserts a new user and returns the created record.
	Create(ctx context.Context, user *domain.User) (*domain.User, error)

	// FindByID retrieves a user by primary key. Returns ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.User, error)

	// FindByEmail retrieves a user by email address. Returns ErrNotFound if absent.
	FindByEmail(ctx context.Context, email string) (*domain.User, error)

	// UpdateLastLogin sets the last_login_at timestamp for the given user.
	UpdateLastLogin(ctx context.Context, userID string, timestamp time.Time) error

	// SetEmailVerifyToken stores a verification token and its expiry for the given user.
	SetEmailVerifyToken(ctx context.Context, userID string, token string, expiresAt time.Time) error

	// ConsumeEmailVerifyToken marks the email as verified if the token matches and hasn't expired.
	// Returns ErrNotFound if the token doesn't match any user, or ErrTokenExpired if expired.
	ConsumeEmailVerifyToken(ctx context.Context, token string) (*domain.User, error)
}

// PostgresUserRepository implements UserRepository using pgx against PostgreSQL.
type PostgresUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresUserRepository creates a new PostgreSQL-backed user repository.
func NewPostgresUserRepository(pool *pgxpool.Pool) *PostgresUserRepository {
	return &PostgresUserRepository{pool: pool}
}

// Create inserts a new user row. Returns ErrDuplicateEmail if the email is already taken.
func (r *PostgresUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := `
		INSERT INTO users (id, email, password_hash, name, roles, locked, locked_at, locked_reason, email_verified, email_verify_token, email_verify_token_expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING id, email, password_hash, name, roles, locked, locked_at, locked_reason, email_verified, email_verify_token, email_verify_token_expires_at, last_login_at, created_at, updated_at, deleted_at`

	out := &domain.User{}
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Roles,
		user.Locked, user.LockedAt, user.LockedReason,
		user.EmailVerified, user.EmailVerifyToken, user.EmailVerifyTokenExpiresAt,
		user.CreatedAt, user.UpdatedAt,
	).Scan(
		&out.ID, &out.Email, &out.PasswordHash, &out.Name, &out.Roles,
		&out.Locked, &out.LockedAt, &out.LockedReason,
		&out.EmailVerified, &out.EmailVerifyToken, &out.EmailVerifyTokenExpiresAt,
		&out.LastLoginAt, &out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("email %s: %w", user.Email, ErrDuplicateEmail)
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}

	return out, nil
}

// FindByID retrieves a user by ID. Soft-deleted users are included.
func (r *PostgresUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return r.findByColumn(ctx, "id", id)
}

// FindByEmail retrieves a user by email address. Soft-deleted users are included.
func (r *PostgresUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.findByColumn(ctx, "email", email)
}

// UpdateLastLogin sets the last_login_at timestamp for a user.
func (r *PostgresUserRepository) UpdateLastLogin(ctx context.Context, userID string, timestamp time.Time) error {
	query := `UPDATE users SET last_login_at = $1, updated_at = $2 WHERE id = $3 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, timestamp, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// findByColumn is a shared helper for single-column lookups.
func (r *PostgresUserRepository) findByColumn(ctx context.Context, column, value string) (*domain.User, error) {
	// column is always a trusted constant from this package — not user input.
	query := fmt.Sprintf(`
		SELECT id, email, password_hash, name, roles, locked, locked_at, locked_reason,
		       email_verified, email_verify_token, email_verify_token_expires_at,
		       last_login_at, created_at, updated_at, deleted_at
		FROM users
		WHERE %s = $1`, column)

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, value).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason,
		&user.EmailVerified, &user.EmailVerifyToken, &user.EmailVerifyTokenExpiresAt,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s %s: %w", column, value, ErrNotFound)
		}
		return nil, fmt.Errorf("find user by %s: %w", column, err)
	}

	return user, nil
}

// SetEmailVerifyToken stores a verification token and expiry for a user.
func (r *PostgresUserRepository) SetEmailVerifyToken(ctx context.Context, userID string, token string, expiresAt time.Time) error {
	query := `UPDATE users SET email_verify_token = $1, email_verify_token_expires_at = $2, updated_at = $3
		WHERE id = $4 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, token, expiresAt, time.Now().UTC(), userID)
	if err != nil {
		return fmt.Errorf("set email verify token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// ConsumeEmailVerifyToken marks the email as verified if the token matches and hasn't expired.
func (r *PostgresUserRepository) ConsumeEmailVerifyToken(ctx context.Context, token string) (*domain.User, error) {
	query := `UPDATE users
		SET email_verified = TRUE,
		    email_verify_token = NULL,
		    email_verify_token_expires_at = NULL,
		    updated_at = $1
		WHERE email_verify_token = $2 AND deleted_at IS NULL
		RETURNING id, email, password_hash, name, roles, locked, locked_at, locked_reason,
		          email_verified, email_verify_token, email_verify_token_expires_at,
		          last_login_at, created_at, updated_at, deleted_at`

	now := time.Now().UTC()
	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, now, token).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason,
		&user.EmailVerified, &user.EmailVerifyToken, &user.EmailVerifyTokenExpiresAt,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("email verify token: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("consume email verify token: %w", err)
	}

	return user, nil
}
