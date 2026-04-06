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

// AgentCredentialRepository defines persistence operations for the encrypted credential vault.
type AgentCredentialRepository interface {
	Create(ctx context.Context, cred *domain.AgentCredential) (*domain.AgentCredential, error)
	GetByID(ctx context.Context, id uuid.UUID) (*domain.AgentCredential, error)
	ListByOwner(ctx context.Context, ownerClientID uuid.UUID) ([]*domain.AgentCredential, error)
	Update(ctx context.Context, cred *domain.AgentCredential) (*domain.AgentCredential, error)
	Delete(ctx context.Context, id uuid.UUID) error
	// GetForBrokering retrieves the active credential for a given owner + target name.
	// Used by the broker flow to look up a credential before injecting it into an agent request.
	GetForBrokering(ctx context.Context, ownerClientID uuid.UUID, targetName string) (*domain.AgentCredential, error)
}

const agentCredentialColumns = `id, owner_client_id, target_name, credential_type, encrypted_blob, scopes, status, last_rotated_at, next_rotation_at, created_at, updated_at`

func scanAgentCredential(row pgx.Row) (*domain.AgentCredential, error) {
	c := &domain.AgentCredential{}
	err := row.Scan(
		&c.ID, &c.OwnerClientID, &c.TargetName, &c.CredentialType,
		&c.EncryptedBlob, &c.Scopes, &c.Status,
		&c.LastRotatedAt, &c.NextRotationAt,
		&c.CreatedAt, &c.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return c, nil
}

// PostgresAgentCredentialRepository implements AgentCredentialRepository using PostgreSQL.
type PostgresAgentCredentialRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAgentCredentialRepository creates a new PostgreSQL-backed credential vault repository.
func NewPostgresAgentCredentialRepository(pool *pgxpool.Pool) *PostgresAgentCredentialRepository {
	return &PostgresAgentCredentialRepository{pool: pool}
}

// Create inserts a new encrypted credential.
func (r *PostgresAgentCredentialRepository) Create(ctx context.Context, cred *domain.AgentCredential) (*domain.AgentCredential, error) {
	query := fmt.Sprintf(`
		INSERT INTO agent_credentials
		    (id, owner_client_id, target_name, credential_type, encrypted_blob, scopes, status, last_rotated_at, next_rotation_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING %s`, agentCredentialColumns)

	c, err := scanAgentCredential(r.pool.QueryRow(ctx, query,
		cred.ID, cred.OwnerClientID, cred.TargetName, cred.CredentialType,
		cred.EncryptedBlob, cred.Scopes, cred.Status,
		cred.LastRotatedAt, cred.NextRotationAt,
		cred.CreatedAt, cred.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert agent credential: %w", err)
	}
	return c, nil
}

// GetByID retrieves a credential by primary key.
func (r *PostgresAgentCredentialRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.AgentCredential, error) {
	query := fmt.Sprintf(`SELECT %s FROM agent_credentials WHERE id = $1`, agentCredentialColumns)
	c, err := scanAgentCredential(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get agent credential %s: %w", id, err)
	}
	return c, nil
}

// ListByOwner returns all credentials belonging to the given owner client, ordered by creation time.
func (r *PostgresAgentCredentialRepository) ListByOwner(ctx context.Context, ownerClientID uuid.UUID) ([]*domain.AgentCredential, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM agent_credentials
		WHERE owner_client_id = $1
		ORDER BY created_at DESC`, agentCredentialColumns)

	rows, err := r.pool.Query(ctx, query, ownerClientID)
	if err != nil {
		return nil, fmt.Errorf("list agent credentials for owner %s: %w", ownerClientID, err)
	}
	defer rows.Close()

	var creds []*domain.AgentCredential
	for rows.Next() {
		c := &domain.AgentCredential{}
		if err := rows.Scan(
			&c.ID, &c.OwnerClientID, &c.TargetName, &c.CredentialType,
			&c.EncryptedBlob, &c.Scopes, &c.Status,
			&c.LastRotatedAt, &c.NextRotationAt,
			&c.CreatedAt, &c.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan agent credential: %w", err)
		}
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate agent credentials: %w", err)
	}

	return creds, nil
}

// Update replaces the mutable fields of a credential (encrypted blob, scopes, rotation timestamps).
// Only active credentials can be updated.
func (r *PostgresAgentCredentialRepository) Update(ctx context.Context, cred *domain.AgentCredential) (*domain.AgentCredential, error) {
	query := fmt.Sprintf(`
		UPDATE agent_credentials
		SET encrypted_blob = $1,
		    scopes = $2,
		    last_rotated_at = $3,
		    next_rotation_at = $4,
		    updated_at = $5
		WHERE id = $6 AND status = 'active'
		RETURNING %s`, agentCredentialColumns)

	c, err := scanAgentCredential(r.pool.QueryRow(ctx, query,
		cred.EncryptedBlob, cred.Scopes,
		cred.LastRotatedAt, cred.NextRotationAt,
		time.Now().UTC(), cred.ID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("agent credential %s: %w", cred.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update agent credential: %w", err)
	}
	return c, nil
}

// Delete marks a credential as revoked (soft-delete).
func (r *PostgresAgentCredentialRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE agent_credentials SET status = 'revoked', updated_at = $1 WHERE id = $2 AND status != 'revoked'`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("delete agent credential %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM agent_credentials WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("agent credential %s already revoked: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("agent credential %s: %w", id, ErrNotFound)
	}
	return nil
}

// GetForBrokering retrieves the active credential for the given owner + target name pair.
// Returns ErrNotFound when no active credential exists for that combination.
func (r *PostgresAgentCredentialRepository) GetForBrokering(ctx context.Context, ownerClientID uuid.UUID, targetName string) (*domain.AgentCredential, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM agent_credentials
		WHERE owner_client_id = $1 AND target_name = $2 AND status = 'active'`, agentCredentialColumns)

	c, err := scanAgentCredential(r.pool.QueryRow(ctx, query, ownerClientID, targetName))
	if err != nil {
		return nil, fmt.Errorf("get credential for brokering (owner=%s target=%s): %w", ownerClientID, targetName, err)
	}
	return c, nil
}
