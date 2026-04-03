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
		INSERT INTO users (id, email, password_hash, name, roles, locked, locked_at, locked_reason, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id, email, password_hash, name, roles, locked, locked_at, locked_reason, last_login_at, created_at, updated_at, deleted_at`

	out := &domain.User{}
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Roles,
		user.Locked, user.LockedAt, user.LockedReason,
		user.CreatedAt, user.UpdatedAt,
	).Scan(
		&out.ID, &out.Email, &out.PasswordHash, &out.Name, &out.Roles,
		&out.Locked, &out.LockedAt, &out.LockedReason, &out.LastLoginAt,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
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
		SELECT id, email, password_hash, name, roles, locked, locked_at, locked_reason, last_login_at, created_at, updated_at, deleted_at
		FROM users
		WHERE %s = $1`, column)

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, value).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason, &user.LastLoginAt,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("%s %s: %w", column, value, ErrNotFound)
		}
		return nil, fmt.Errorf("find user by %s: %w", column, err)
	}

	return user, nil
}
