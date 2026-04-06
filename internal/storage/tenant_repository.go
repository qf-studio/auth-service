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

// TenantRepository defines persistence operations for tenant management.
type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	FindByID(ctx context.Context, id string) (*domain.Tenant, error)
	FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.Tenant, int, error)
	Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	Delete(ctx context.Context, id string) error
}

// PostgresTenantRepository implements TenantRepository using PostgreSQL.
type PostgresTenantRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresTenantRepository creates a new PostgreSQL-backed tenant repository.
func NewPostgresTenantRepository(pool *pgxpool.Pool) *PostgresTenantRepository {
	return &PostgresTenantRepository{pool: pool}
}

const tenantColumns = `id, slug, name, active, created_at, updated_at, deleted_at`

func scanTenant(row pgx.Row) (*domain.Tenant, error) {
	t := &domain.Tenant{}
	err := row.Scan(&t.ID, &t.Slug, &t.Name, &t.Active, &t.CreatedAt, &t.UpdatedAt, &t.DeletedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return t, nil
}

// Create inserts a new tenant. Returns ErrDuplicateTenantSlug on slug conflict.
func (r *PostgresTenantRepository) Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	query := fmt.Sprintf(`
		INSERT INTO tenants (id, slug, name, active, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, tenantColumns)

	t, err := scanTenant(r.pool.QueryRow(ctx, query,
		tenant.ID, tenant.Slug, tenant.Name, tenant.Active,
		tenant.CreatedAt, tenant.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("tenant slug %s: %w", tenant.Slug, ErrDuplicateTenantSlug)
		}
		return nil, fmt.Errorf("insert tenant: %w", err)
	}
	return t, nil
}

// FindByID retrieves a tenant by primary key (excludes soft-deleted).
func (r *PostgresTenantRepository) FindByID(ctx context.Context, id string) (*domain.Tenant, error) {
	query := fmt.Sprintf(`SELECT %s FROM tenants WHERE id = $1 AND deleted_at IS NULL`, tenantColumns)
	t, err := scanTenant(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find tenant %s: %w", id, err)
	}
	return t, nil
}

// FindBySlug retrieves a tenant by slug (excludes soft-deleted).
func (r *PostgresTenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	query := fmt.Sprintf(`SELECT %s FROM tenants WHERE slug = $1 AND deleted_at IS NULL`, tenantColumns)
	t, err := scanTenant(r.pool.QueryRow(ctx, query, slug))
	if err != nil {
		return nil, fmt.Errorf("find tenant %s: %w", slug, err)
	}
	return t, nil
}

// List returns a paginated list of tenants. When includeDeleted is false,
// soft-deleted tenants are excluded.
func (r *PostgresTenantRepository) List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.Tenant, int, error) {
	whereClause := ""
	if !includeDeleted {
		whereClause = "WHERE deleted_at IS NULL"
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM tenants %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM tenants %s ORDER BY created_at DESC LIMIT $1 OFFSET $2`,
		tenantColumns, whereClause)
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*domain.Tenant
	for rows.Next() {
		t := &domain.Tenant{}
		if err := rows.Scan(&t.ID, &t.Slug, &t.Name, &t.Active, &t.CreatedAt, &t.UpdatedAt, &t.DeletedAt); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate tenants: %w", err)
	}

	return tenants, total, nil
}

// Update modifies mutable fields of a tenant (name, slug, active).
func (r *PostgresTenantRepository) Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	query := fmt.Sprintf(`
		UPDATE tenants SET name = $1, slug = $2, active = $3, updated_at = $4
		WHERE id = $5 AND deleted_at IS NULL
		RETURNING %s`, tenantColumns)

	t, err := scanTenant(r.pool.QueryRow(ctx, query,
		tenant.Name, tenant.Slug, tenant.Active, time.Now().UTC(), tenant.ID,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("tenant slug %s: %w", tenant.Slug, ErrDuplicateTenantSlug)
		}
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenant.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	return t, nil
}

// Delete soft-deletes a tenant by setting deleted_at.
func (r *PostgresTenantRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE tenants SET deleted_at = $1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("soft delete tenant %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("tenant %s already deleted: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("tenant %s: %w", id, ErrNotFound)
	}
	return nil
}
