package client

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// PostgresRepository implements Repository using PostgreSQL via pgx.
type PostgresRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRepository creates a new PostgresRepository backed by the given pool.
func NewPostgresRepository(pool *pgxpool.Pool) *PostgresRepository {
	return &PostgresRepository{pool: pool}
}

func (r *PostgresRepository) Create(ctx context.Context, client *domain.Client) error {
	const q = `
		INSERT INTO clients (id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, q,
		client.ID,
		client.Name,
		client.ClientType,
		client.SecretHash,
		client.Scopes,
		client.Owner,
		client.AccessTokenTTL,
		client.Status,
		client.CreatedAt,
		client.UpdatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert client: %w", err)
	}
	return nil
}

func (r *PostgresRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	const q = `
		SELECT id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at, last_used_at
		FROM clients WHERE id = $1`

	return r.scanClient(r.pool.QueryRow(ctx, q, id))
}

func (r *PostgresRepository) GetByName(ctx context.Context, name string) (*domain.Client, error) {
	const q = `
		SELECT id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at, last_used_at
		FROM clients WHERE name = $1`

	return r.scanClient(r.pool.QueryRow(ctx, q, name))
}

func (r *PostgresRepository) List(ctx context.Context, owner string) ([]*domain.Client, error) {
	const q = `
		SELECT id, name, client_type, secret_hash, scopes, owner, access_token_ttl, status, created_at, updated_at, last_used_at
		FROM clients WHERE owner = $1 ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, owner)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}
	defer rows.Close()

	var clients []*domain.Client
	for rows.Next() {
		c, err := r.scanClient(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list clients rows: %w", err)
	}
	return clients, nil
}

func (r *PostgresRepository) Update(ctx context.Context, client *domain.Client) error {
	const q = `
		UPDATE clients SET name=$1, scopes=$2, access_token_ttl=$3, status=$4, updated_at=$5
		WHERE id=$6`

	tag, err := r.pool.Exec(ctx, q,
		client.Name,
		client.Scopes,
		client.AccessTokenTTL,
		client.Status,
		client.UpdatedAt,
		client.ID,
	)
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

func (r *PostgresRepository) Delete(ctx context.Context, id uuid.UUID) error {
	const q = `DELETE FROM clients WHERE id = $1`

	tag, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrClientNotFound
	}
	return nil
}

func (r *PostgresRepository) UpdateLastUsed(ctx context.Context, id uuid.UUID) error {
	const q = `UPDATE clients SET last_used_at = now() WHERE id = $1`

	_, err := r.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("update last_used_at: %w", err)
	}
	return nil
}

// scanClient scans a single row into a domain.Client.
func (r *PostgresRepository) scanClient(row pgx.Row) (*domain.Client, error) {
	var c domain.Client
	err := row.Scan(
		&c.ID,
		&c.Name,
		&c.ClientType,
		&c.SecretHash,
		&c.Scopes,
		&c.Owner,
		&c.AccessTokenTTL,
		&c.Status,
		&c.CreatedAt,
		&c.UpdatedAt,
		&c.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrClientNotFound
		}
		return nil, fmt.Errorf("scan client: %w", err)
	}
	return &c, nil
}
