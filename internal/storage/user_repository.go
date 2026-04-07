package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
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
	FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)

	// FindByEmail retrieves a user by email address. Returns ErrNotFound if absent.
	FindByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error)

	// UpdateLastLogin sets the last_login_at timestamp for the given user.
	UpdateLastLogin(ctx context.Context, tenantID uuid.UUID, userID string, timestamp time.Time) error

	// SetEmailVerifyToken stores a verification token and its expiry for the given user.
	SetEmailVerifyToken(ctx context.Context, tenantID uuid.UUID, userID string, token string, expiresAt time.Time) error

	// ConsumeEmailVerifyToken marks the email as verified if the token matches and hasn't expired.
	// Returns ErrNotFound if the token doesn't match any user, or ErrTokenExpired if expired.
	ConsumeEmailVerifyToken(ctx context.Context, tenantID uuid.UUID, token string) (*domain.User, error)

	// UpdatePasswordHash updates a user's password hash and password_changed_at timestamp.
	// Also clears force_password_change flag.
	UpdatePasswordHash(ctx context.Context, tenantID uuid.UUID, userID, newHash string) error

	// SetForcePasswordChange sets the force_password_change flag for a user.
	SetForcePasswordChange(ctx context.Context, tenantID uuid.UUID, userID string, force bool) error

	// GetPasswordHistory returns the most recent N password history entries for a user,
	// ordered newest-first.
	GetPasswordHistory(ctx context.Context, tenantID uuid.UUID, userID string, limit int) ([]domain.PasswordHistoryEntry, error)

	// AddPasswordHistory appends a password hash to the user's history.
	AddPasswordHistory(ctx context.Context, tenantID uuid.UUID, userID, passwordHash string) error
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
		INSERT INTO users (id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason, email_verified, email_verify_token, email_verify_token_expires_at, force_password_change, password_changed_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)
		RETURNING id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason, email_verified, email_verify_token, email_verify_token_expires_at, last_login_at, force_password_change, password_changed_at, created_at, updated_at, deleted_at`

	out := &domain.User{}
	err := r.pool.QueryRow(ctx, query,
		user.ID, user.TenantID, user.Email, user.PasswordHash, user.Name, user.Roles,
		user.Locked, user.LockedAt, user.LockedReason,
		user.EmailVerified, user.EmailVerifyToken, user.EmailVerifyTokenExpiresAt,
		user.ForcePasswordChange, user.PasswordChangedAt,
		user.CreatedAt, user.UpdatedAt,
	).Scan(
		&out.ID, &out.TenantID, &out.Email, &out.PasswordHash, &out.Name, &out.Roles,
		&out.Locked, &out.LockedAt, &out.LockedReason,
		&out.EmailVerified, &out.EmailVerifyToken, &out.EmailVerifyTokenExpiresAt,
		&out.LastLoginAt, &out.ForcePasswordChange, &out.PasswordChangedAt,
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
func (r *PostgresUserRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	return r.findByColumn(ctx, tenantID, "id", id)
}

// FindByEmail retrieves a user by email address. Soft-deleted users are included.
func (r *PostgresUserRepository) FindByEmail(ctx context.Context, tenantID uuid.UUID, email string) (*domain.User, error) {
	return r.findByColumn(ctx, tenantID, "email", email)
}

// UpdateLastLogin sets the last_login_at timestamp for a user.
func (r *PostgresUserRepository) UpdateLastLogin(ctx context.Context, tenantID uuid.UUID, userID string, timestamp time.Time) error {
	query := `UPDATE users SET last_login_at = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, timestamp, time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("update last login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// findByColumn is a shared helper for single-column lookups.
func (r *PostgresUserRepository) findByColumn(ctx context.Context, tenantID uuid.UUID, column, value string) (*domain.User, error) {
	// column is always a trusted constant from this package — not user input.
	query := fmt.Sprintf(`
		SELECT id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason,
		       email_verified, email_verify_token, email_verify_token_expires_at,
		       last_login_at, force_password_change, password_changed_at,
		       created_at, updated_at, deleted_at
		FROM users
		WHERE %s = $1 AND tenant_id = $2`, column)

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, value, tenantID).Scan(
		&user.ID, &user.TenantID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason,
		&user.EmailVerified, &user.EmailVerifyToken, &user.EmailVerifyTokenExpiresAt,
		&user.LastLoginAt, &user.ForcePasswordChange, &user.PasswordChangedAt,
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

// SetEmailVerifyToken stores a verification token and expiry for a user.
func (r *PostgresUserRepository) SetEmailVerifyToken(ctx context.Context, tenantID uuid.UUID, userID string, token string, expiresAt time.Time) error {
	query := `UPDATE users SET email_verify_token = $1, email_verify_token_expires_at = $2, updated_at = $3
		WHERE id = $4 AND tenant_id = $5 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, token, expiresAt, time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("set email verify token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// ConsumeEmailVerifyToken marks the email as verified if the token matches and hasn't expired.
func (r *PostgresUserRepository) ConsumeEmailVerifyToken(ctx context.Context, tenantID uuid.UUID, token string) (*domain.User, error) {
	query := `UPDATE users
		SET email_verified = TRUE,
		    email_verify_token = NULL,
		    email_verify_token_expires_at = NULL,
		    updated_at = $1
		WHERE email_verify_token = $2 AND tenant_id = $3 AND deleted_at IS NULL
		RETURNING id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason,
		          email_verified, email_verify_token, email_verify_token_expires_at,
		          last_login_at, force_password_change, password_changed_at,
		          created_at, updated_at, deleted_at`

	now := time.Now().UTC()
	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, now, token, tenantID).Scan(
		&user.ID, &user.TenantID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason,
		&user.EmailVerified, &user.EmailVerifyToken, &user.EmailVerifyTokenExpiresAt,
		&user.LastLoginAt, &user.ForcePasswordChange, &user.PasswordChangedAt,
		&user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("email verify token: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("consume email verify token: %w", err)
	}

	return user, nil
}

// UpdatePasswordHash updates a user's password hash and marks password_changed_at.
// Clears force_password_change flag.
func (r *PostgresUserRepository) UpdatePasswordHash(ctx context.Context, tenantID uuid.UUID, userID, newHash string) error {
	now := time.Now().UTC()
	query := `UPDATE users
		SET password_hash = $1, password_changed_at = $2, force_password_change = FALSE, updated_at = $2
		WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, newHash, now, userID, tenantID)
	if err != nil {
		return fmt.Errorf("update password hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}
	return nil
}

// SetForcePasswordChange sets the force_password_change flag for a user.
func (r *PostgresUserRepository) SetForcePasswordChange(ctx context.Context, tenantID uuid.UUID, userID string, force bool) error {
	query := `UPDATE users SET force_password_change = $1, updated_at = $2 WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL`
	tag, err := r.pool.Exec(ctx, query, force, time.Now().UTC(), userID, tenantID)
	if err != nil {
		return fmt.Errorf("set force password change: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}
	return nil
}

// GetPasswordHistory returns the most recent N password history entries for a user.
func (r *PostgresUserRepository) GetPasswordHistory(ctx context.Context, tenantID uuid.UUID, userID string, limit int) ([]domain.PasswordHistoryEntry, error) {
	query := `SELECT id, tenant_id, user_id, password_hash, created_at
		FROM password_history
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY created_at DESC
		LIMIT $3`

	rows, err := r.pool.Query(ctx, query, userID, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("get password history: %w", err)
	}
	defer rows.Close()

	var entries []domain.PasswordHistoryEntry
	for rows.Next() {
		var e domain.PasswordHistoryEntry
		if err := rows.Scan(&e.ID, &e.TenantID, &e.UserID, &e.PasswordHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// AddPasswordHistory appends a password hash to the user's history.
func (r *PostgresUserRepository) AddPasswordHistory(ctx context.Context, tenantID uuid.UUID, userID, passwordHash string) error {
	query := `INSERT INTO password_history (tenant_id, user_id, password_hash) VALUES ($1, $2, $3)`
	_, err := r.pool.Exec(ctx, query, tenantID, userID, passwordHash)
	if err != nil {
		return fmt.Errorf("add password history: %w", err)
	}
	return nil
}
