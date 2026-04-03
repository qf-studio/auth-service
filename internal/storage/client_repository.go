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

// ClientRepository defines persistence operations for OAuth2 clients.
type ClientRepository interface {
	// Create inserts a new client. Returns ErrDuplicateClient if name is already taken.
	Create(ctx context.Context, client *domain.Client) (*domain.Client, error)

	// FindByID retrieves a client by UUID string. Returns ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.Client, error)

	// List returns a paginated list of clients and the total count.
	// When includeRevoked is false, clients with status "revoked" are excluded.
	List(ctx context.Context, page, perPage int, includeRevoked bool) ([]*domain.Client, int, error)

	// Update modifies a client record. Returns ErrNotFound if absent.
	Update(ctx context.Context, client *domain.Client) (*domain.Client, error)

	// Delete soft-deletes a client by setting its status to "revoked".
	// Returns ErrNotFound if absent or already revoked.
	Delete(ctx context.Context, id string) error

	// UpdateLastUsedAt sets the last_used_at timestamp for a client.
	UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error
}

// PostgresClientRepository implements ClientRepository using pgx against PostgreSQL.
type PostgresClientRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresClientRepository creates a new PostgreSQL-backed client repository.
func NewPostgresClientRepository(pool *pgxpool.Pool) *PostgresClientRepository {
	return &PostgresClientRepository{pool: pool}
}

const clientScanColumns = `id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at, last_used_at`

// scanClientRow scans a single client row into a domain.Client.
func scanClientRow(row pgx.Row) (*domain.Client, error) {
	c := &domain.Client{}
	var clientTypeStr string
	err := row.Scan(
		&c.ID, &c.Name, &clientTypeStr, &c.SecretHash, &c.Scopes,
		&c.Owner, &c.AccessTokenTTL, &c.Status,
		&c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt,
	)
	if err != nil {
		return nil, err
	}
	c.ClientType = domain.ClientType(clientTypeStr)
	return c, nil
}

// Create inserts a new client. Returns ErrDuplicateClient if the name is already taken.
func (r *PostgresClientRepository) Create(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	query := `
		INSERT INTO clients (id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING ` + clientScanColumns

	out, err := scanClientRow(r.pool.QueryRow(ctx, query,
		client.ID, client.Name, string(client.ClientType), client.SecretHash, client.Scopes,
		client.Owner, client.AccessTokenTTL, client.Status,
		client.CreatedAt, client.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("client %s: %w", client.Name, ErrDuplicateClient)
		}
		return nil, fmt.Errorf("insert client: %w", err)
	}
	return out, nil
}

// FindByID retrieves a client by its UUID string. Returns ErrNotFound if absent.
func (r *PostgresClientRepository) FindByID(ctx context.Context, id string) (*domain.Client, error) {
	query := `SELECT ` + clientScanColumns + ` FROM clients WHERE id = $1`

	out, err := scanClientRow(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("client %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("find client by id: %w", err)
	}
	return out, nil
}

// List retrieves a paginated list of clients and the total matching count.
func (r *PostgresClientRepository) List(ctx context.Context, page, perPage int, includeRevoked bool) ([]*domain.Client, int, error) {
	if page < 1 {
		page = 1
	}
	offset := (page - 1) * perPage

	// Build optional WHERE clause.
	filter := " WHERE status != 'revoked'"
	if includeRevoked {
		filter = ""
	}

	var total int
	countQuery := `SELECT COUNT(*) FROM clients` + filter
	if err := r.pool.QueryRow(ctx, countQuery).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count clients: %w", err)
	}

	listQuery := `SELECT ` + clientScanColumns + ` FROM clients` + filter + ` ORDER BY created_at DESC LIMIT $1 OFFSET $2`
	rows, err := r.pool.Query(ctx, listQuery, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		c := &domain.Client{}
		var clientTypeStr string
		if err := rows.Scan(
			&c.ID, &c.Name, &clientTypeStr, &c.SecretHash, &c.Scopes,
			&c.Owner, &c.AccessTokenTTL, &c.Status,
			&c.CreatedAt, &c.UpdatedAt, &c.LastUsedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan client row: %w", err)
		}
		c.ClientType = domain.ClientType(clientTypeStr)
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate clients: %w", err)
	}

	return clients, total, nil
}

// Update modifies the name, scopes, access_token_ttl, status, and secret_hash of a client.
func (r *PostgresClientRepository) Update(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	query := `
		UPDATE clients
		SET name = $1, scopes = $2, access_token_ttl = $3, status = $4, secret_hash = $5, updated_at = $6
		WHERE id = $7
		RETURNING ` + clientScanColumns

	out, err := scanClientRow(r.pool.QueryRow(ctx, query,
		client.Name, client.Scopes, client.AccessTokenTTL, client.Status, client.SecretHash,
		time.Now().UTC(), client.ID,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("client %s: %w", client.ID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("client name %s: %w", client.Name, ErrDuplicateClient)
		}
		return nil, fmt.Errorf("update client: %w", err)
	}
	return out, nil
}

// Delete soft-deletes a client by setting its status to "revoked".
func (r *PostgresClientRepository) Delete(ctx context.Context, id string) error {
	query := `UPDATE clients SET status = 'revoked', updated_at = $1 WHERE id = $2 AND status != 'revoked'`

	tag, err := r.pool.Exec(ctx, query, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("client %s: %w", id, ErrNotFound)
	}
	return nil
}

// UpdateLastUsedAt sets the last_used_at timestamp for a client.
func (r *PostgresClientRepository) UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error {
	query := `UPDATE clients SET last_used_at = $1, updated_at = $2 WHERE id = $3`

	_, err := r.pool.Exec(ctx, query, t, time.Now().UTC(), id)
	if err != nil {
		return fmt.Errorf("update client last_used_at: %w", err)
	}
	return nil
}
