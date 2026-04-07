package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// ErrDuplicateTenantSlug indicates a tenant with the given slug already exists.
var ErrDuplicateTenantSlug = errors.New("duplicate tenant slug")

// TenantRepository defines CRUD operations for the tenants table.
type TenantRepository interface {
	// Create inserts a new tenant and returns the created record.
	Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)

	// FindByID retrieves a tenant by its UUID primary key.
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)

	// FindBySlug retrieves a tenant by its unique slug.
	FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error)

	// List returns a paginated list of tenants, optionally filtered by status.
	List(ctx context.Context, limit, offset int, status string) ([]*domain.Tenant, int, error)

	// Update persists changes to a tenant record.
	Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)

	// Delete performs a soft delete by setting status to "deleted".
	Delete(ctx context.Context, id uuid.UUID) error
}

// PostgresTenantRepository implements TenantRepository using pgx against PostgreSQL.
type PostgresTenantRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresTenantRepository creates a new PostgreSQL-backed tenant repository.
func NewPostgresTenantRepository(pool *pgxpool.Pool) *PostgresTenantRepository {
	return &PostgresTenantRepository{pool: pool}
}

// Create inserts a new tenant row.
func (r *PostgresTenantRepository) Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	configJSON, err := json.Marshal(tenant.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant config: %w", err)
	}

	query := `
		INSERT INTO tenants (id, name, slug, config, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, name, slug, config, status, created_at, updated_at`

	out := &domain.Tenant{}
	var cfgBytes []byte
	err = r.pool.QueryRow(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, configJSON, tenant.Status,
		tenant.CreatedAt, tenant.UpdatedAt,
	).Scan(
		&out.ID, &out.Name, &out.Slug, &cfgBytes, &out.Status,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("slug %s: %w", tenant.Slug, ErrDuplicateTenantSlug)
		}
		return nil, fmt.Errorf("insert tenant: %w", err)
	}

	if err := json.Unmarshal(cfgBytes, &out.Config); err != nil {
		return nil, fmt.Errorf("unmarshal tenant config: %w", err)
	}

	return out, nil
}

// FindByID retrieves a tenant by UUID.
func (r *PostgresTenantRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	return r.findByColumn(ctx, "id", id)
}

// FindBySlug retrieves a tenant by slug.
func (r *PostgresTenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	return r.findByColumn(ctx, "slug", slug)
}

func (r *PostgresTenantRepository) findByColumn(ctx context.Context, column string, value interface{}) (*domain.Tenant, error) {
	query := fmt.Sprintf(`
		SELECT id, name, slug, config, status, created_at, updated_at
		FROM tenants
		WHERE %s = $1`, column)

	t := &domain.Tenant{}
	var cfgBytes []byte
	err := r.pool.QueryRow(ctx, query, value).Scan(
		&t.ID, &t.Name, &t.Slug, &cfgBytes, &t.Status,
		&t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tenant %s=%v: %w", column, value, ErrNotFound)
		}
		return nil, fmt.Errorf("find tenant by %s: %w", column, err)
	}

	if err := json.Unmarshal(cfgBytes, &t.Config); err != nil {
		return nil, fmt.Errorf("unmarshal tenant config: %w", err)
	}

	return t, nil
}

// List returns a paginated list of tenants.
func (r *PostgresTenantRepository) List(ctx context.Context, limit, offset int, status string) ([]*domain.Tenant, int, error) {
	var countQuery string
	var listQuery string
	var args []interface{}

	if status != "" {
		countQuery = `SELECT count(*) FROM tenants WHERE status = $1`
		listQuery = `SELECT id, name, slug, config, status, created_at, updated_at
			FROM tenants WHERE status = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`
		args = []interface{}{status, limit, offset}
	} else {
		countQuery = `SELECT count(*) FROM tenants`
		listQuery = `SELECT id, name, slug, config, status, created_at, updated_at
			FROM tenants ORDER BY created_at DESC LIMIT $1 OFFSET $2`
		args = []interface{}{limit, offset}
	}

	// Count total.
	var total int
	var countArgs []interface{}
	if status != "" {
		countArgs = []interface{}{status}
	}
	if err := r.pool.QueryRow(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	rows, err := r.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*domain.Tenant
	for rows.Next() {
		t := &domain.Tenant{}
		var cfgBytes []byte
		if err := rows.Scan(&t.ID, &t.Name, &t.Slug, &cfgBytes, &t.Status, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		if err := json.Unmarshal(cfgBytes, &t.Config); err != nil {
			return nil, 0, fmt.Errorf("unmarshal tenant config: %w", err)
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate tenants: %w", err)
	}

	return tenants, total, nil
}

// Update persists changes to a tenant.
func (r *PostgresTenantRepository) Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	configJSON, err := json.Marshal(tenant.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant config: %w", err)
	}

	now := time.Now().UTC()
	query := `
		UPDATE tenants SET name = $1, slug = $2, config = $3, status = $4, updated_at = $5
		WHERE id = $6
		RETURNING id, name, slug, config, status, created_at, updated_at`

	out := &domain.Tenant{}
	var cfgBytes []byte
	err = r.pool.QueryRow(ctx, query,
		tenant.Name, tenant.Slug, configJSON, tenant.Status, now, tenant.ID,
	).Scan(
		&out.ID, &out.Name, &out.Slug, &cfgBytes, &out.Status,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tenant %s: %w", tenant.ID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("slug %s: %w", tenant.Slug, ErrDuplicateTenantSlug)
		}
		return nil, fmt.Errorf("update tenant: %w", err)
	}

	if err := json.Unmarshal(cfgBytes, &out.Config); err != nil {
		return nil, fmt.Errorf("unmarshal tenant config: %w", err)
	}

	return out, nil
}

// Delete performs a soft delete by setting status to "deleted".
func (r *PostgresTenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()
	query := `UPDATE tenants SET status = $1, updated_at = $2 WHERE id = $3 AND status != $1`

	tag, err := r.pool.Exec(ctx, query, domain.TenantStatusDeleted, now, id)
	if err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant %s: %w", id, ErrNotFound)
	}
	return nil
}
