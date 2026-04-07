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

// TenantRepository defines persistence operations for tenant management.
type TenantRepository interface {
	Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
	FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error)
	List(ctx context.Context, limit, offset int, status string) ([]*domain.Tenant, int, error)
	Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// PostgresTenantRepository implements TenantRepository using PostgreSQL.
type PostgresTenantRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresTenantRepository creates a new PostgreSQL-backed tenant repository.
func NewPostgresTenantRepository(pool *pgxpool.Pool) *PostgresTenantRepository {
	return &PostgresTenantRepository{pool: pool}
}

const tenantColumns = `id, name, slug, config, status, created_at, updated_at`

func scanTenant(row pgx.Row) (*domain.Tenant, error) {
	t := &domain.Tenant{}
	var configJSON []byte
	err := row.Scan(
		&t.ID, &t.Name, &t.Slug, &configJSON,
		&t.Status, &t.CreatedAt, &t.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(configJSON) > 0 {
		if err := json.Unmarshal(configJSON, &t.Config); err != nil {
			return nil, fmt.Errorf("unmarshal tenant config: %w", err)
		}
	}
	return t, nil
}

// Create inserts a new tenant. Returns ErrDuplicateTenant on slug conflict.
func (r *PostgresTenantRepository) Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	configJSON, err := json.Marshal(tenant.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant config: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO tenants (id, name, slug, config, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, tenantColumns)

	result, err := scanTenant(r.pool.QueryRow(ctx, query,
		tenant.ID, tenant.Name, tenant.Slug, configJSON,
		tenant.Status, tenant.CreatedAt, tenant.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("tenant slug %s: %w", tenant.Slug, ErrDuplicateTenant)
		}
		return nil, fmt.Errorf("insert tenant: %w", err)
	}
	return result, nil
}

// FindByID retrieves a tenant by primary key.
func (r *PostgresTenantRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	query := fmt.Sprintf(`SELECT %s FROM tenants WHERE id = $1`, tenantColumns)
	t, err := scanTenant(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find tenant %s: %w", id, err)
	}
	return t, nil
}

// FindBySlug retrieves a tenant by its unique slug.
func (r *PostgresTenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	query := fmt.Sprintf(`SELECT %s FROM tenants WHERE slug = $1`, tenantColumns)
	t, err := scanTenant(r.pool.QueryRow(ctx, query, slug))
	if err != nil {
		return nil, fmt.Errorf("find tenant %q: %w", slug, err)
	}
	return t, nil
}

// List returns a paginated list of tenants ordered by name, optionally filtered by status.
func (r *PostgresTenantRepository) List(ctx context.Context, limit, offset int, status string) ([]*domain.Tenant, int, error) {
	var total int
	args := []interface{}{}
	where := ""
	if status != "" {
		where = " WHERE status = $1"
		args = append(args, status)
	}

	countQuery := `SELECT COUNT(*) FROM tenants` + where
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count tenants: %w", err)
	}

	limitIdx := len(args) + 1
	offsetIdx := len(args) + 2
	query := fmt.Sprintf(`SELECT %s FROM tenants%s ORDER BY name LIMIT $%d OFFSET $%d`,
		tenantColumns, where, limitIdx, offsetIdx)
	listArgs := append(args, limit, offset)
	rows, err := r.pool.Query(ctx, query, listArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	defer rows.Close()

	var tenants []*domain.Tenant
	for rows.Next() {
		t := &domain.Tenant{}
		var configJSON []byte
		if err := rows.Scan(
			&t.ID, &t.Name, &t.Slug, &configJSON,
			&t.Status, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan tenant: %w", err)
		}
		if len(configJSON) > 0 {
			if err := json.Unmarshal(configJSON, &t.Config); err != nil {
				return nil, 0, fmt.Errorf("unmarshal tenant config: %w", err)
			}
		}
		tenants = append(tenants, t)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate tenants: %w", err)
	}

	return tenants, total, nil
}

// Update modifies a tenant's mutable fields (name, config, status).
func (r *PostgresTenantRepository) Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	configJSON, err := json.Marshal(tenant.Config)
	if err != nil {
		return nil, fmt.Errorf("marshal tenant config: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE tenants SET name = $1, config = $2, status = $3, updated_at = $4
		WHERE id = $5
		RETURNING %s`, tenantColumns)

	result, err := scanTenant(r.pool.QueryRow(ctx, query,
		tenant.Name, configJSON, tenant.Status, time.Now().UTC(), tenant.ID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenant.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	return result, nil
}

// Delete removes a tenant by ID.
func (r *PostgresTenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM tenants WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete tenant %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tenant %s: %w", id, ErrNotFound)
	}
	return nil
}
