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

// ClientRepository defines persistence operations for OAuth2 client management.
type ClientRepository interface {
	List(ctx context.Context, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	FindByName(ctx context.Context, name string) (*domain.Client, error)
	Create(ctx context.Context, client *domain.Client) (*domain.Client, error)
	Update(ctx context.Context, client *domain.Client) (*domain.Client, error)
	UpdateSecretHash(ctx context.Context, id uuid.UUID, secretHash string) error
	RotateSecret(ctx context.Context, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

// PostgresClientRepository implements ClientRepository using PostgreSQL.
type PostgresClientRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresClientRepository creates a new PostgreSQL-backed client repository.
func NewPostgresClientRepository(pool *pgxpool.Pool) *PostgresClientRepository {
	return &PostgresClientRepository{pool: pool}
}

const clientColumns = `id, name, client_type, secret_hash, previous_secret_hash, previous_secret_expires_at, scopes, owner, access_token_ttl, status, created_at, updated_at, last_used_at`

func scanClient(row pgx.Row) (*domain.Client, error) {
	c := &domain.Client{}
	err := row.Scan(
		&c.ID, &c.Name, &c.ClientType, &c.SecretHash,
		&c.PreviousSecretHash, &c.PreviousSecretExpiresAt,
		&c.Scopes, &c.Owner, &c.AccessTokenTTL, &c.Status,
		&c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

// List returns a paginated list of clients filtered by clientType and revocation status.
func (r *PostgresClientRepository) List(ctx context.Context, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error) {
	// Build WHERE clause and args with parameterized queries to avoid SQL injection.
	var conditions []string
	var args []interface{}
	argIdx := 1

	if !includeRevoked {
		conditions = append(conditions, "status != 'revoked'")
	}
	if clientType != "" {
		conditions = append(conditions, fmt.Sprintf("client_type = $%d", argIdx))
		args = append(args, clientType)
		argIdx++
	}

	whereClause := ""
	if len(conditions) > 0 {
		whereClause = "WHERE " + conditions[0]
		for _, c := range conditions[1:] {
			whereClause += " AND " + c
		}
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM clients %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count clients: %w", err)
	}

	limitArgIdx := argIdx
	offsetArgIdx := argIdx + 1
	query := fmt.Sprintf(`SELECT %s FROM clients %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`, clientColumns, whereClause, limitArgIdx, offsetArgIdx)
	queryArgs := append(args, limit, offset)
	rows, err := r.pool.Query(ctx, query, queryArgs...)
	if err != nil {
		return nil, 0, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		c := &domain.Client{}
		if err := rows.Scan(
			&c.ID, &c.Name, &c.ClientType, &c.SecretHash,
			&c.PreviousSecretHash, &c.PreviousSecretExpiresAt,
			&c.Scopes, &c.Owner, &c.AccessTokenTTL, &c.Status,
			&c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan client: %w", err)
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate clients: %w", err)
	}

	return clients, total, nil
}

// FindByID retrieves a client by primary key.
func (r *PostgresClientRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	query := fmt.Sprintf(`SELECT %s FROM clients WHERE id = $1`, clientColumns)
	c, err := scanClient(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find client %s: %w", id, err)
	}
	return c, nil
}

// FindByName retrieves a client by name.
func (r *PostgresClientRepository) FindByName(ctx context.Context, name string) (*domain.Client, error) {
	query := fmt.Sprintf(`SELECT %s FROM clients WHERE name = $1`, clientColumns)
	c, err := scanClient(r.pool.QueryRow(ctx, query, name))
	if err != nil {
		return nil, fmt.Errorf("find client %s: %w", name, err)
	}
	return c, nil
}

// Create inserts a new client. Returns ErrDuplicateClient on name conflict.
func (r *PostgresClientRepository) Create(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	query := fmt.Sprintf(`
		INSERT INTO clients (id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, clientColumns)

	c, err := scanClient(r.pool.QueryRow(ctx, query,
		client.ID, client.Name, client.ClientType, client.SecretHash,
		client.Scopes, client.Owner, client.AccessTokenTTL, client.Status,
		client.CreatedAt, client.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("client name %s: %w", client.Name, ErrDuplicateClient)
		}
		return nil, fmt.Errorf("insert client: %w", err)
	}
	return c, nil
}

// Update modifies mutable fields of a client (name, scopes).
func (r *PostgresClientRepository) Update(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	query := fmt.Sprintf(`
		UPDATE clients SET name = $1, scopes = $2, updated_at = $3
		WHERE id = $4 AND status != 'revoked'
		RETURNING %s`, clientColumns)

	c, err := scanClient(r.pool.QueryRow(ctx, query,
		client.Name, client.Scopes, time.Now().UTC(), client.ID,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("client name %s: %w", client.Name, ErrDuplicateClient)
		}
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", client.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update client: %w", err)
	}
	return c, nil
}

// UpdateSecretHash replaces the secret hash for the given client.
func (r *PostgresClientRepository) UpdateSecretHash(ctx context.Context, id uuid.UUID, secretHash string) error {
	query := `UPDATE clients SET secret_hash = $1, updated_at = $2 WHERE id = $3 AND status != 'revoked'`
	tag, err := r.pool.Exec(ctx, query, secretHash, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update secret hash: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("client %s: %w", id, ErrNotFound)
	}
	return nil
}

// RotateSecret moves the current secret to previous_secret_hash with a grace period,
// then sets the new secret hash. Both secrets are valid until the grace period expires.
func (r *PostgresClientRepository) RotateSecret(ctx context.Context, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error {
	query := `
		UPDATE clients
		SET previous_secret_hash = secret_hash,
		    previous_secret_expires_at = $1,
		    secret_hash = $2,
		    updated_at = $3
		WHERE id = $4 AND status != 'revoked'`

	now := time.Now().UTC()
	tag, err := r.pool.Exec(ctx, query, gracePeriodEnds, newSecretHash, now, id)
	if err != nil {
		return fmt.Errorf("rotate secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("client %s: %w", id, ErrNotFound)
	}
	return nil
}

// SoftDelete marks a client as revoked.
func (r *PostgresClientRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE clients SET status = 'revoked', updated_at = $1 WHERE id = $2 AND status != 'revoked'`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("soft delete client %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM clients WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("client %s already deleted: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("client %s: %w", id, ErrNotFound)
	}
	return nil
}
