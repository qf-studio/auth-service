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

// AdminUserRepository defines persistence operations for admin user management.
type AdminUserRepository interface {
	List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.User, int, error)
	FindByID(ctx context.Context, id string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) (*domain.User, error)
	SoftDelete(ctx context.Context, id string) error
	Lock(ctx context.Context, id, reason string) (*domain.User, error)
	Unlock(ctx context.Context, id string) (*domain.User, error)
}

// PostgresAdminUserRepository implements AdminUserRepository using PostgreSQL.
type PostgresAdminUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAdminUserRepository creates a new PostgreSQL-backed admin user repository.
func NewPostgresAdminUserRepository(pool *pgxpool.Pool) *PostgresAdminUserRepository {
	return &PostgresAdminUserRepository{pool: pool}
}

const userColumns = `id, email, password_hash, name, roles, locked, locked_at, locked_reason, last_login_at, created_at, updated_at, deleted_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	err := row.Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles,
		&u.Locked, &u.LockedAt, &u.LockedReason, &u.LastLoginAt,
		&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// List returns a paginated list of users. When includeDeleted is false, soft-deleted users are excluded.
func (r *PostgresAdminUserRepository) List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.User, int, error) {
	whereClause := ""
	if !includeDeleted {
		whereClause = "WHERE deleted_at IS NULL"
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM users %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM users %s ORDER BY created_at DESC LIMIT $1 OFFSET $2`, userColumns, whereClause)
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(
			&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles,
			&u.Locked, &u.LockedAt, &u.LockedReason, &u.LastLoginAt,
			&u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan user: %w", err)
		}
		users = append(users, u)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate users: %w", err)
	}

	return users, total, nil
}

// FindByID retrieves a user by ID, including soft-deleted users.
func (r *PostgresAdminUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE id = $1`, userColumns)
	u, err := scanUser(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find user %s: %w", id, err)
	}
	return u, nil
}

// Create inserts a new user. Returns ErrDuplicateEmail on unique constraint violation.
func (r *PostgresAdminUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := fmt.Sprintf(`
		INSERT INTO users (id, email, password_hash, name, roles, locked, locked_at, locked_reason, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query,
		user.ID, user.Email, user.PasswordHash, user.Name, user.Roles,
		user.Locked, user.LockedAt, user.LockedReason,
		user.CreatedAt, user.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("email %s: %w", user.Email, ErrDuplicateEmail)
		}
		return nil, fmt.Errorf("insert user: %w", err)
	}
	return u, nil
}

// Update modifies mutable fields of a user (email, name, roles).
func (r *PostgresAdminUserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := fmt.Sprintf(`
		UPDATE users SET email = $1, name = $2, roles = $3, updated_at = $4
		WHERE id = $5 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query,
		user.Email, user.Name, user.Roles, time.Now().UTC(), user.ID,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("email %s: %w", user.Email, ErrDuplicateEmail)
		}
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", user.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update user: %w", err)
	}
	return u, nil
}

// SoftDelete sets deleted_at on the user record.
func (r *PostgresAdminUserRepository) SoftDelete(ctx context.Context, id string) error {
	query := `UPDATE users SET deleted_at = $1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("soft delete user %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		// Check if user exists but is already deleted.
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("user %s already deleted: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("user %s: %w", id, ErrNotFound)
	}
	return nil
}

// Lock sets the locked flag and reason on a user.
func (r *PostgresAdminUserRepository) Lock(ctx context.Context, id, reason string) (*domain.User, error) {
	now := time.Now().UTC()
	query := fmt.Sprintf(`
		UPDATE users SET locked = true, locked_at = $1, locked_reason = $2, updated_at = $1
		WHERE id = $3 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query, now, reason, id))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("lock user %s: %w", id, err)
	}
	return u, nil
}

// Unlock clears the locked flag and reason on a user.
func (r *PostgresAdminUserRepository) Unlock(ctx context.Context, id string) (*domain.User, error) {
	now := time.Now().UTC()
	query := fmt.Sprintf(`
		UPDATE users SET locked = false, locked_at = NULL, locked_reason = '', updated_at = $1
		WHERE id = $2 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query, now, id))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("unlock user %s: %w", id, err)
	}
	return u, nil
}

