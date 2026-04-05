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

// PostgresWebAuthnRepository implements WebAuthnRepository using pgx against PostgreSQL.
type PostgresWebAuthnRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebAuthnRepository creates a new PostgreSQL-backed WebAuthn credential repository.
func NewPostgresWebAuthnRepository(pool *pgxpool.Pool) *PostgresWebAuthnRepository {
	return &PostgresWebAuthnRepository{pool: pool}
}

// credentialColumns is the shared SELECT column list for WebAuthn credentials.
const credentialColumns = `id, user_id, credential_id, public_key, aaguid, sign_count, transports, attestation_type, friendly_name, created_at, updated_at, deleted_at`

// scanCredential scans a row into a WebAuthnCredential.
func scanCredential(row pgx.Row) (*domain.WebAuthnCredential, error) {
	c := &domain.WebAuthnCredential{}
	err := row.Scan(
		&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
		&c.AAGUID, &c.SignCount, &c.Transports, &c.AttestationType,
		&c.FriendlyName, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt,
	)
	return c, err
}

// Create inserts a new WebAuthn credential.
func (r *PostgresWebAuthnRepository) Create(ctx context.Context, cred *domain.WebAuthnCredential) (*domain.WebAuthnCredential, error) {
	query := `
		INSERT INTO webauthn_credentials (id, user_id, credential_id, public_key, aaguid, sign_count, transports, attestation_type, friendly_name, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING ` + credentialColumns

	out, err := scanCredential(r.pool.QueryRow(ctx, query,
		cred.ID, cred.UserID, cred.CredentialID, cred.PublicKey,
		cred.AAGUID, cred.SignCount, cred.Transports, cred.AttestationType,
		cred.FriendlyName, cred.CreatedAt, cred.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("credential already registered: %w", ErrDuplicateWebAuthn)
		}
		return nil, fmt.Errorf("insert webauthn credential: %w", err)
	}

	return out, nil
}

// GetByUser returns all active credentials for a user, ordered by creation time.
func (r *PostgresWebAuthnRepository) GetByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	query := `SELECT ` + credentialColumns + `
		FROM webauthn_credentials
		WHERE user_id = $1 AND deleted_at IS NULL
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get webauthn credentials by user: %w", err)
	}
	defer rows.Close()

	var creds []domain.WebAuthnCredential
	for rows.Next() {
		var c domain.WebAuthnCredential
		if err := rows.Scan(
			&c.ID, &c.UserID, &c.CredentialID, &c.PublicKey,
			&c.AAGUID, &c.SignCount, &c.Transports, &c.AttestationType,
			&c.FriendlyName, &c.CreatedAt, &c.UpdatedAt, &c.DeletedAt,
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

// GetByCredentialID retrieves an active credential by its raw credential ID.
func (r *PostgresWebAuthnRepository) GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error) {
	query := `SELECT ` + credentialColumns + `
		FROM webauthn_credentials
		WHERE credential_id = $1 AND deleted_at IS NULL`

	out, err := scanCredential(r.pool.QueryRow(ctx, query, credentialID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("credential: %w", ErrNotFound)
		}
		return nil, fmt.Errorf("get webauthn credential by credential_id: %w", err)
	}

	return out, nil
}

// UpdateSignCount sets the new sign count and bumps updated_at.
func (r *PostgresWebAuthnRepository) UpdateSignCount(ctx context.Context, id string, newCount uint32) error {
	now := time.Now().UTC()
	query := `
		UPDATE webauthn_credentials
		SET sign_count = $1, updated_at = $2
		WHERE id = $3 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, newCount, now, id)
	if err != nil {
		return fmt.Errorf("update webauthn sign count: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %s: %w", id, ErrNotFound)
	}

	return nil
}

// Delete hard-deletes a credential row.
func (r *PostgresWebAuthnRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM webauthn_credentials WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete webauthn credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %s: %w", id, ErrNotFound)
	}

	return nil
}

// SoftDelete marks a credential as deleted by setting deleted_at.
func (r *PostgresWebAuthnRepository) SoftDelete(ctx context.Context, id string) error {
	now := time.Now().UTC()
	query := `
		UPDATE webauthn_credentials
		SET deleted_at = $1, updated_at = $2
		WHERE id = $3 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, now, now, id)
	if err != nil {
		return fmt.Errorf("soft-delete webauthn credential: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("credential %s: %w", id, ErrNotFound)
	}

	return nil
}
