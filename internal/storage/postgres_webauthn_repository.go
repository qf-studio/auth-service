package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// PostgresWebAuthnRepository implements WebAuthnRepository using pgx against PostgreSQL.
type PostgresWebAuthnRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebAuthnRepository creates a new PostgreSQL-backed WebAuthn credential repository.
func NewPostgresWebAuthnRepository(pool *pgxpool.Pool) *PostgresWebAuthnRepository {
	return &PostgresWebAuthnRepository{pool: pool}
}

// CreateCredential stores a new WebAuthn credential.
func (r *PostgresWebAuthnRepository) CreateCredential(ctx context.Context, cred *domain.WebAuthnCredential) error {
	query := `
		INSERT INTO webauthn_credentials
			(id, user_id, credential_id, public_key, attestation_type, aaguid, sign_count, transports, name, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`

	_, err := r.pool.Exec(ctx, query,
		cred.ID, cred.UserID, cred.CredentialID, cred.PublicKey,
		cred.AttestationType, cred.AAGUID, cred.SignCount,
		cred.Transports, cred.Name, cred.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert webauthn credential: %w", err)
	}
	return nil
}

// GetCredentialsByUser returns all active credentials for a user.
func (r *PostgresWebAuthnRepository) GetCredentialsByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type, aaguid,
		       sign_count, transports, name, created_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query webauthn credentials: %w", err)
	}
	defer rows.Close()

	var creds []domain.WebAuthnCredential
	for rows.Next() {
		var c domain.WebAuthnCredential
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
			&c.AttestationType, &c.AAGUID, &c.SignCount,
			&c.Transports, &c.Name, &c.CreatedAt, &c.LastUsedAt, &c.DeletedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webauthn credential: %w", err)
		}
		creds = append(creds, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webauthn credentials: %w", err)
	}
	return creds, nil
}

// GetCredentialByCredentialID retrieves a credential by its raw credential ID.
func (r *PostgresWebAuthnRepository) GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error) {
	query := `
		SELECT id, user_id, credential_id, public_key, attestation_type, aaguid,
		       sign_count, transports, name, created_at, last_used_at, deleted_at
		FROM webauthn_credentials
		WHERE credential_id = $1 AND deleted_at IS NULL`

	var c domain.WebAuthnCredential
	err := r.pool.QueryRow(ctx, query, credentialID).Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
		&c.AttestationType, &c.AAGUID, &c.SignCount,
		&c.Transports, &c.Name, &c.CreatedAt, &c.LastUsedAt, &c.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get webauthn credential by credential_id: %w", err)
	}
	return &c, nil
}

// UpdateSignCount updates the sign counter and last-used timestamp.
func (r *PostgresWebAuthnRepository) UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error {
	query := `
		UPDATE webauthn_credentials
		SET sign_count = $1, last_used_at = $2
		WHERE credential_id = $3 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, signCount, time.Now().UTC(), credentialID)
	if err != nil {
		return fmt.Errorf("update webauthn sign count: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// DeleteCredential soft-deletes a credential by its UUID, scoped to the owning user.
func (r *PostgresWebAuthnRepository) DeleteCredential(ctx context.Context, userID, id string) error {
	query := `
		UPDATE webauthn_credentials
		SET deleted_at = $1
		WHERE id = $2 AND user_id = $3 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, time.Now().UTC(), id, userID)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}
