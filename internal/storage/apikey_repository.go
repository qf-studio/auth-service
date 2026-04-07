package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// APIKeyRepository defines persistence operations for API key management.
type APIKeyRepository interface {
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientID string) ([]*domain.APIKey, int, error)
	FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.APIKey, error)
	FindByKeyHash(ctx context.Context, tenantID uuid.UUID, keyHash string) (*domain.APIKey, error)
	Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	Revoke(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	RotateKey(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
	UpdateLastUsed(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

const apiKeyColumns = `id, tenant_id, client_id, name, key_hash, previous_key_hash, previous_key_expires_at, key_prefix, scopes, rate_limit, status, expires_at, last_used_at, created_at, updated_at`

func scanAPIKey(row pgx.Row) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	err := row.Scan(
		&k.ID, &k.TenantID, &k.ClientID, &k.Name, &k.KeyHash,
		&k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
		&k.KeyPrefix, &k.Scopes, &k.RateLimit, &k.Status,
		&k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return k, nil
}

// PostgresAPIKeyRepository implements APIKeyRepository using PostgreSQL.
type PostgresAPIKeyRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAPIKeyRepository creates a new PostgreSQL-backed API key repository.
func NewPostgresAPIKeyRepository(pool *pgxpool.Pool) *PostgresAPIKeyRepository {
	return &PostgresAPIKeyRepository{pool: pool}
}

// List returns a paginated list of API keys, optionally filtered by client_id.
func (r *PostgresAPIKeyRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientID string) ([]*domain.APIKey, int, error) {
	args := []interface{}{tenantID}
	conditions := []string{fmt.Sprintf("tenant_id = $%d", len(args))}

	if clientID != "" {
		args = append(args, clientID)
		conditions = append(conditions, fmt.Sprintf("client_id = $%d", len(args)))
	}

	whereClause := "WHERE " + conditions[0]
	for _, cond := range conditions[1:] {
		whereClause += " AND " + cond
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM api_keys %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api keys: %w", err)
	}

	paginationOffset := len(args)
	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT %s FROM api_keys %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		apiKeyColumns, whereClause, paginationOffset+1, paginationOffset+2)
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		k := &domain.APIKey{}
		if err := rows.Scan(
			&k.ID, &k.TenantID, &k.ClientID, &k.Name, &k.KeyHash,
			&k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
			&k.KeyPrefix, &k.Scopes, &k.RateLimit, &k.Status,
			&k.ExpiresAt, &k.LastUsedAt, &k.CreatedAt, &k.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan api key: %w", err)
		}
		keys = append(keys, k)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate api keys: %w", err)
	}

	return keys, total, nil
}

// FindByID retrieves an API key by primary key.
func (r *PostgresAPIKeyRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.APIKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM api_keys WHERE id = $1 AND tenant_id = $2`, apiKeyColumns)
	k, err := scanAPIKey(r.pool.QueryRow(ctx, query, id, tenantID))
	if err != nil {
		return nil, fmt.Errorf("find api key %s: %w", id, err)
	}
	return k, nil
}

// FindByKeyHash retrieves an API key by its hashed key value.
func (r *PostgresAPIKeyRepository) FindByKeyHash(ctx context.Context, tenantID uuid.UUID, keyHash string) (*domain.APIKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM api_keys WHERE (key_hash = $1 OR (previous_key_hash = $1 AND previous_key_expires_at > NOW())) AND tenant_id = $2`, apiKeyColumns)
	k, err := scanAPIKey(r.pool.QueryRow(ctx, query, keyHash, tenantID))
	if err != nil {
		return nil, fmt.Errorf("find api key by hash: %w", err)
	}
	return k, nil
}

// Create inserts a new API key.
func (r *PostgresAPIKeyRepository) Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	query := fmt.Sprintf(`
		INSERT INTO api_keys (id, tenant_id, client_id, name, key_hash, key_prefix, scopes, rate_limit, status, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING %s`, apiKeyColumns)

	k, err := scanAPIKey(r.pool.QueryRow(ctx, query,
		key.ID, key.TenantID, key.ClientID, key.Name, key.KeyHash,
		key.KeyPrefix, key.Scopes, key.RateLimit, key.Status,
		key.ExpiresAt, key.CreatedAt, key.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert api key: %w", err)
	}
	return k, nil
}

// Update modifies mutable fields of an API key (name, scopes, rate_limit).
func (r *PostgresAPIKeyRepository) Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	query := fmt.Sprintf(`
		UPDATE api_keys SET name = $1, scopes = $2, rate_limit = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6 AND status = 'active'
		RETURNING %s`, apiKeyColumns)

	k, err := scanAPIKey(r.pool.QueryRow(ctx, query,
		key.Name, key.Scopes, key.RateLimit, time.Now().UTC(), key.ID, key.TenantID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", key.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update api key: %w", err)
	}
	return k, nil
}

// Revoke marks an API key as revoked.
func (r *PostgresAPIKeyRepository) Revoke(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `UPDATE api_keys SET status = 'revoked', updated_at = $1 WHERE id = $2 AND tenant_id = $3 AND status = 'active'`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id, tenantID)
	if err != nil {
		return fmt.Errorf("revoke api key %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_keys WHERE id = $1 AND tenant_id = $2)`, id, tenantID).Scan(&exists)
		if exists {
			return fmt.Errorf("api key %s already revoked: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("api key %s: %w", id, ErrNotFound)
	}
	return nil
}

// RotateKey moves the current key hash to previous_key_hash with a grace period,
// then sets the new key hash.
func (r *PostgresAPIKeyRepository) RotateKey(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	query := `
		UPDATE api_keys
		SET previous_key_hash = key_hash,
		    previous_key_expires_at = $1,
		    key_hash = $2,
		    updated_at = $3
		WHERE id = $4 AND tenant_id = $5 AND status = 'active'`

	now := time.Now().UTC()
	tag, err := r.pool.Exec(ctx, query, gracePeriodEnds, newKeyHash, now, id, tenantID)
	if err != nil {
		return fmt.Errorf("rotate api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key %s: %w", id, ErrNotFound)
	}
	return nil
}

// UpdateLastUsed sets the last_used_at timestamp for the given API key.
func (r *PostgresAPIKeyRepository) UpdateLastUsed(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `UPDATE api_keys SET last_used_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return fmt.Errorf("update last used: %w", err)
	}
	return nil
}
