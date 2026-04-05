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

// APIKeyRepository defines persistence operations for API key management.
type APIKeyRepository interface {
	Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.APIKey, error)
	FindByHash(ctx context.Context, keyHash string) (*domain.APIKey, error)
	ListByClientID(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]*domain.APIKey, int, error)
	Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
	RotateKey(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
}

// PostgresAPIKeyRepository implements APIKeyRepository using PostgreSQL.
type PostgresAPIKeyRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAPIKeyRepository creates a new PostgreSQL-backed API key repository.
func NewPostgresAPIKeyRepository(pool *pgxpool.Pool) *PostgresAPIKeyRepository {
	return &PostgresAPIKeyRepository{pool: pool}
}

const apiKeyColumns = `id, client_id, name, key_hash, previous_key_hash, previous_key_expires_at, scopes, rate_limit, status, expires_at, last_used_at, created_at, updated_at`

func scanAPIKey(row pgx.Row) (*domain.APIKey, error) {
	k := &domain.APIKey{}
	err := row.Scan(
		&k.ID, &k.ClientID, &k.Name, &k.KeyHash,
		&k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
		&k.Scopes, &k.RateLimit, &k.Status,
		&k.ExpiresAt, &k.LastUsedAt,
		&k.CreatedAt, &k.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return k, nil
}

// Create inserts a new API key. Returns ErrDuplicateAPIKey on (client_id, name) conflict.
func (r *PostgresAPIKeyRepository) Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	query := fmt.Sprintf(`
		INSERT INTO api_keys (id, client_id, name, key_hash, scopes, rate_limit, status, expires_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, apiKeyColumns)

	k, err := scanAPIKey(r.pool.QueryRow(ctx, query,
		key.ID, key.ClientID, key.Name, key.KeyHash,
		key.Scopes, key.RateLimit, key.Status,
		key.ExpiresAt, key.CreatedAt, key.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("api key name %s for client %s: %w", key.Name, key.ClientID, ErrDuplicateAPIKey)
		}
		return nil, fmt.Errorf("insert api key: %w", err)
	}
	return k, nil
}

// FindByID retrieves an API key by primary key.
func (r *PostgresAPIKeyRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.APIKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM api_keys WHERE id = $1`, apiKeyColumns)
	k, err := scanAPIKey(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find api key %s: %w", id, err)
	}
	return k, nil
}

// FindByHash retrieves an active API key by its key hash.
func (r *PostgresAPIKeyRepository) FindByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	query := fmt.Sprintf(`SELECT %s FROM api_keys WHERE key_hash = $1 AND status = 'active'`, apiKeyColumns)
	k, err := scanAPIKey(r.pool.QueryRow(ctx, query, keyHash))
	if err != nil {
		return nil, fmt.Errorf("find api key by hash: %w", err)
	}
	return k, nil
}

// ListByClientID returns a paginated list of API keys for a given client.
func (r *PostgresAPIKeyRepository) ListByClientID(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]*domain.APIKey, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM api_keys WHERE client_id = $1`, clientID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count api keys: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM api_keys WHERE client_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3`, apiKeyColumns)
	rows, err := r.pool.Query(ctx, query, clientID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list api keys: %w", err)
	}
	defer rows.Close()

	var keys []*domain.APIKey
	for rows.Next() {
		k := &domain.APIKey{}
		if err := rows.Scan(
			&k.ID, &k.ClientID, &k.Name, &k.KeyHash,
			&k.PreviousKeyHash, &k.PreviousKeyExpiresAt,
			&k.Scopes, &k.RateLimit, &k.Status,
			&k.ExpiresAt, &k.LastUsedAt,
			&k.CreatedAt, &k.UpdatedAt,
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

// Update modifies mutable fields of an API key (name, scopes, rate_limit, expires_at).
func (r *PostgresAPIKeyRepository) Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	query := fmt.Sprintf(`
		UPDATE api_keys SET name = $1, scopes = $2, rate_limit = $3, expires_at = $4, updated_at = $5
		WHERE id = $6 AND status = 'active'
		RETURNING %s`, apiKeyColumns)

	k, err := scanAPIKey(r.pool.QueryRow(ctx, query,
		key.Name, key.Scopes, key.RateLimit, key.ExpiresAt, time.Now().UTC(), key.ID,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("api key name %s: %w", key.Name, ErrDuplicateAPIKey)
		}
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", key.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update api key: %w", err)
	}
	return k, nil
}

// SoftDelete marks an API key as revoked.
func (r *PostgresAPIKeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE api_keys SET status = 'revoked', updated_at = $1 WHERE id = $2 AND status = 'active'`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("soft delete api key %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM api_keys WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("api key %s already revoked: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("api key %s: %w", id, ErrNotFound)
	}
	return nil
}

// RotateKey moves the current key hash to previous_key_hash with a grace period,
// then sets the new key hash. Both keys are valid until the grace period expires.
func (r *PostgresAPIKeyRepository) RotateKey(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	query := `
		UPDATE api_keys
		SET previous_key_hash = key_hash,
		    previous_key_expires_at = $1,
		    key_hash = $2,
		    updated_at = $3
		WHERE id = $4 AND status = 'active'`

	now := time.Now().UTC()
	tag, err := r.pool.Exec(ctx, query, gracePeriodEnds, newKeyHash, now, id)
	if err != nil {
		return fmt.Errorf("rotate api key: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("api key %s: %w", id, ErrNotFound)
	}
	return nil
}
