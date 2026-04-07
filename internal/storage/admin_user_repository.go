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

// UserSearchFilter defines advanced search criteria for listing users.
type UserSearchFilter struct {
	Email         string     // partial match (ILIKE)
	Role          string     // exact match against roles array
	Status        string     // active, locked, suspended, deleted
	CreatedAfter  *time.Time // created_at >= value
	CreatedBefore *time.Time // created_at <= value
}

// AdminUserRepository defines persistence operations for admin user management.
type AdminUserRepository interface {
	// List returns a paginated list of users, filtered by status.
	// Valid status values: "" (all non-deleted), "active" (non-locked, non-deleted),
	// "locked" (locked, non-deleted), "deleted" (soft-deleted only).
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int, status string) ([]*domain.User, int, error)
	// SearchUsers returns a paginated list of users matching the given filters.
	SearchUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int, filter UserSearchFilter) ([]*domain.User, int, error)
	FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
	Update(ctx context.Context, user *domain.User) (*domain.User, error)
	SoftDelete(ctx context.Context, tenantID uuid.UUID, id string) error
	Lock(ctx context.Context, tenantID uuid.UUID, id, reason string) (*domain.User, error)
	Unlock(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
	// BulkUpdateStatus applies a status change (lock, unlock, or suspend) to multiple users at once.
	// Returns the number of affected rows.
	BulkUpdateStatus(ctx context.Context, tenantID uuid.UUID, ids []string, action string, reason string) (int64, error)
	// BulkAssignRole adds a role to all specified users (no-op if user already has it).
	// Returns the number of affected rows.
	BulkAssignRole(ctx context.Context, tenantID uuid.UUID, ids []string, role string) (int64, error)
}

// PostgresAdminUserRepository implements AdminUserRepository using PostgreSQL.
type PostgresAdminUserRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAdminUserRepository creates a new PostgreSQL-backed admin user repository.
func NewPostgresAdminUserRepository(pool *pgxpool.Pool) *PostgresAdminUserRepository {
	return &PostgresAdminUserRepository{pool: pool}
}

const userColumns = `id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason, email_verified, email_verify_token, email_verify_token_expires_at, last_login_at, created_at, updated_at, deleted_at`

func scanUser(row pgx.Row) (*domain.User, error) {
	u := &domain.User{}
	err := row.Scan(
		&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles,
		&u.Locked, &u.LockedAt, &u.LockedReason,
		&u.EmailVerified, &u.EmailVerifyToken, &u.EmailVerifyTokenExpiresAt,
		&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return u, nil
}

// List returns a paginated list of users filtered by status.
// Status values: "" (all non-deleted), "active", "locked", "deleted".
func (r *PostgresAdminUserRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, status string) ([]*domain.User, int, error) {
	var whereClause string
	switch status {
	case "active":
		whereClause = "WHERE tenant_id = $1 AND deleted_at IS NULL AND locked = false"
	case "locked":
		whereClause = "WHERE tenant_id = $1 AND deleted_at IS NULL AND locked = true"
	case "deleted":
		whereClause = "WHERE tenant_id = $1 AND deleted_at IS NOT NULL"
	default:
		whereClause = "WHERE tenant_id = $1 AND deleted_at IS NULL"
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM users %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM users %s ORDER BY created_at DESC LIMIT $2 OFFSET $3`, userColumns, whereClause)
	rows, err := r.pool.Query(ctx, query, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(
			&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles,
			&u.Locked, &u.LockedAt, &u.LockedReason,
			&u.EmailVerified, &u.EmailVerifyToken, &u.EmailVerifyTokenExpiresAt,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
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

// SearchUsers returns a paginated list of users matching the given filters.
func (r *PostgresAdminUserRepository) SearchUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int, filter UserSearchFilter) ([]*domain.User, int, error) {
	conditions := []string{"tenant_id = $1"}
	args := []interface{}{tenantID}
	argIdx := 2

	// Status filter.
	switch filter.Status {
	case "active":
		conditions = append(conditions, "deleted_at IS NULL AND locked = false")
	case "locked":
		conditions = append(conditions, "deleted_at IS NULL AND locked = true")
	case "suspended":
		conditions = append(conditions, "deleted_at IS NOT NULL")
	case "deleted":
		conditions = append(conditions, "deleted_at IS NOT NULL")
	default:
		conditions = append(conditions, "deleted_at IS NULL")
	}

	// Email partial match.
	if filter.Email != "" {
		conditions = append(conditions, fmt.Sprintf("email ILIKE $%d", argIdx))
		args = append(args, "%"+filter.Email+"%")
		argIdx++
	}

	// Role exact match.
	if filter.Role != "" {
		conditions = append(conditions, fmt.Sprintf("$%d = ANY(roles)", argIdx))
		args = append(args, filter.Role)
		argIdx++
	}

	// Date range filters.
	if filter.CreatedAfter != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, *filter.CreatedAfter)
		argIdx++
	}
	if filter.CreatedBefore != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, *filter.CreatedBefore)
		argIdx++
	}

	whereClause := "WHERE " + conditions[0]
	for i := 1; i < len(conditions); i++ {
		whereClause += " AND " + conditions[i]
	}

	// Count query.
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM users %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count users: %w", err)
	}

	// Data query.
	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT %s FROM users %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		userColumns, whereClause, argIdx, argIdx+1)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("search users: %w", err)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u := &domain.User{}
		if err := rows.Scan(
			&u.ID, &u.TenantID, &u.Email, &u.PasswordHash, &u.Name, &u.Roles,
			&u.Locked, &u.LockedAt, &u.LockedReason,
			&u.EmailVerified, &u.EmailVerifyToken, &u.EmailVerifyTokenExpiresAt,
			&u.LastLoginAt, &u.CreatedAt, &u.UpdatedAt, &u.DeletedAt,
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

// BulkUpdateStatus applies a status change to multiple users at once.
// Supported actions: "lock", "unlock", "suspend".
func (r *PostgresAdminUserRepository) BulkUpdateStatus(ctx context.Context, tenantID uuid.UUID, ids []string, action string, reason string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	var query string

	switch action {
	case "lock":
		query = `UPDATE users SET locked = true, locked_at = $1, locked_reason = $2, updated_at = $1
			WHERE id = ANY($3) AND tenant_id = $4 AND deleted_at IS NULL`
	case "unlock":
		query = `UPDATE users SET locked = false, locked_at = NULL, locked_reason = '', updated_at = $1
			WHERE id = ANY($3) AND tenant_id = $4 AND deleted_at IS NULL`
	case "suspend":
		query = `UPDATE users SET deleted_at = $1, updated_at = $1
			WHERE id = ANY($3) AND tenant_id = $4 AND deleted_at IS NULL`
	default:
		return 0, fmt.Errorf("unsupported bulk action: %s", action)
	}

	tag, err := r.pool.Exec(ctx, query, now, reason, ids, tenantID)
	if err != nil {
		return 0, fmt.Errorf("bulk %s users: %w", action, err)
	}
	return tag.RowsAffected(), nil
}

// BulkAssignRole adds a role to all specified users who don't already have it.
func (r *PostgresAdminUserRepository) BulkAssignRole(ctx context.Context, tenantID uuid.UUID, ids []string, role string) (int64, error) {
	if len(ids) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	query := `UPDATE users SET roles = array_append(roles, $1), updated_at = $2
		WHERE id = ANY($3) AND tenant_id = $4 AND deleted_at IS NULL AND NOT ($1 = ANY(roles))`

	tag, err := r.pool.Exec(ctx, query, role, now, ids, tenantID)
	if err != nil {
		return 0, fmt.Errorf("bulk assign role: %w", err)
	}
	return tag.RowsAffected(), nil
}

// FindByID retrieves a user by ID, including soft-deleted users.
func (r *PostgresAdminUserRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE id = $1 AND tenant_id = $2`, userColumns)
	u, err := scanUser(r.pool.QueryRow(ctx, query, id, tenantID))
	if err != nil {
		return nil, fmt.Errorf("find user %s: %w", id, err)
	}
	return u, nil
}

// Create inserts a new user. Returns ErrDuplicateEmail on unique constraint violation.
func (r *PostgresAdminUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	query := fmt.Sprintf(`
		INSERT INTO users (id, tenant_id, email, password_hash, name, roles, locked, locked_at, locked_reason, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query,
		user.ID, user.TenantID, user.Email, user.PasswordHash, user.Name, user.Roles,
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
		WHERE id = $5 AND tenant_id = $6 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query,
		user.Email, user.Name, user.Roles, time.Now().UTC(), user.ID, user.TenantID,
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
func (r *PostgresAdminUserRepository) SoftDelete(ctx context.Context, tenantID uuid.UUID, id string) error {
	query := `UPDATE users SET deleted_at = $1, updated_at = $1 WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id, tenantID)
	if err != nil {
		return fmt.Errorf("soft delete user %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		// Check if user exists but is already deleted.
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE id = $1 AND tenant_id = $2)`, id, tenantID).Scan(&exists)
		if exists {
			return fmt.Errorf("user %s already deleted: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("user %s: %w", id, ErrNotFound)
	}
	return nil
}

// Lock sets the locked flag and reason on a user.
func (r *PostgresAdminUserRepository) Lock(ctx context.Context, tenantID uuid.UUID, id, reason string) (*domain.User, error) {
	now := time.Now().UTC()
	query := fmt.Sprintf(`
		UPDATE users SET locked = true, locked_at = $1, locked_reason = $2, updated_at = $1
		WHERE id = $3 AND tenant_id = $4 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query, now, reason, id, tenantID))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("lock user %s: %w", id, err)
	}
	return u, nil
}

// Unlock clears the locked flag and reason on a user.
func (r *PostgresAdminUserRepository) Unlock(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	now := time.Now().UTC()
	query := fmt.Sprintf(`
		UPDATE users SET locked = false, locked_at = NULL, locked_reason = '', updated_at = $1
		WHERE id = $2 AND tenant_id = $3 AND deleted_at IS NULL
		RETURNING %s`, userColumns)

	u, err := scanUser(r.pool.QueryRow(ctx, query, now, id, tenantID))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("unlock user %s: %w", id, err)
	}
	return u, nil
}
