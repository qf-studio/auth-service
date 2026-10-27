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
	"github.com/qf-studio/auth-service/internal/secretbox"
)

// PostgresMFARepository implements MFARepository using pgx against PostgreSQL.
type PostgresMFARepository struct {
	pool *pgxpool.Pool
	box  *secretbox.Box
}

// NewPostgresMFARepository creates a new PostgreSQL-backed MFA repository.
// box seals TOTP secrets at rest; a nil box stores them in plaintext (the
// DATA_ENCRYPTION_KEY-unset behaviour).
func NewPostgresMFARepository(pool *pgxpool.Pool, box *secretbox.Box) *PostgresMFARepository {
	return &PostgresMFARepository{pool: pool, box: box}
}

// SaveSecret inserts a new MFA secret for a user.
func (r *PostgresMFARepository) SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	query := `
		INSERT INTO mfa_secrets (id, tenant_id, user_id, type, secret, confirmed, confirmed_at, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, tenant_id, user_id, type, secret, confirmed, confirmed_at, created_at, updated_at, deleted_at`

	sealed, err := r.box.Encrypt(secret.Secret)
	if err != nil {
		return nil, fmt.Errorf("encrypt mfa secret: %w", err)
	}

	out := &domain.MFASecret{}
	err = r.pool.QueryRow(ctx, query,
		secret.ID, secret.TenantID, secret.UserID, secret.Type, sealed,
		secret.Confirmed, secret.ConfirmedAt,
		secret.CreatedAt, secret.UpdatedAt,
	).Scan(
		&out.ID, &out.TenantID, &out.UserID, &out.Type, &out.Secret,
		&out.Confirmed, &out.ConfirmedAt,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("user %s type %s: %w", secret.UserID, secret.Type, ErrDuplicateMFA)
		}
		return nil, fmt.Errorf("insert mfa secret: %w", err)
	}
	// Callers get the usable secret back, never the stored ciphertext.
	out.Secret = secret.Secret

	return out, nil
}

// GetSecret retrieves the active MFA secret for a user.
func (r *PostgresMFARepository) GetSecret(ctx context.Context, tenantID uuid.UUID, userID string) (*domain.MFASecret, error) {
	query := `
		SELECT id, tenant_id, user_id, type, secret, confirmed, confirmed_at, created_at, updated_at, deleted_at
		FROM mfa_secrets
		WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL`

	out := &domain.MFASecret{}
	err := r.pool.QueryRow(ctx, query, userID, tenantID).Scan(
		&out.ID, &out.TenantID, &out.UserID, &out.Type, &out.Secret,
		&out.Confirmed, &out.ConfirmedAt,
		&out.CreatedAt, &out.UpdatedAt, &out.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user %s: %w", userID, ErrNotFound)
		}
		return nil, fmt.Errorf("get mfa secret: %w", err)
	}

	stored := out.Secret
	out.Secret, err = r.box.Decrypt(stored)
	if err != nil {
		return nil, fmt.Errorf("decrypt mfa secret for user %s: %w", userID, err)
	}

	// A legacy plaintext row is sealed on first read once a key is configured.
	// Best effort: the secret is already in hand, and the one-shot
	// EncryptExistingSecrets job covers rows that are never read.
	if r.box.Enabled() && !secretbox.IsEncrypted(stored) {
		if err := r.sealSecretRow(ctx, out.ID, stored, out.Secret); err != nil {
			// Not fatal: verification must still work.
			return out, nil
		}
	}

	return out, nil
}

// sealSecretRow replaces a legacy plaintext secret with its sealed form. The
// compare-and-set on the old value keeps a concurrent re-enrolment safe.
func (r *PostgresMFARepository) sealSecretRow(ctx context.Context, id, oldValue, plaintext string) error {
	sealed, err := r.box.Encrypt(plaintext)
	if err != nil {
		return fmt.Errorf("encrypt mfa secret: %w", err)
	}
	if _, err := r.pool.Exec(ctx, `UPDATE mfa_secrets SET secret = $1 WHERE id = $2 AND secret = $3`, sealed, id, oldValue); err != nil {
		return fmt.Errorf("rewrite mfa secret: %w", err)
	}
	return nil
}

// ConfirmSecret marks the user's MFA secret as confirmed.
func (r *PostgresMFARepository) ConfirmSecret(ctx context.Context, tenantID uuid.UUID, userID string) error {
	now := time.Now().UTC()
	query := `
		UPDATE mfa_secrets
		SET confirmed = TRUE, confirmed_at = $1, updated_at = $2
		WHERE user_id = $3 AND tenant_id = $4 AND deleted_at IS NULL AND confirmed = FALSE`

	tag, err := r.pool.Exec(ctx, query, now, now, userID, tenantID)
	if err != nil {
		return fmt.Errorf("confirm mfa secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// DeleteSecret soft-deletes the user's active MFA secret.
func (r *PostgresMFARepository) DeleteSecret(ctx context.Context, tenantID uuid.UUID, userID string) error {
	now := time.Now().UTC()
	query := `
		UPDATE mfa_secrets
		SET deleted_at = $1, updated_at = $2
		WHERE user_id = $3 AND tenant_id = $4 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, now, now, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete mfa secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// SaveBackupCodes stores hashed backup codes, deleting any existing unused codes first.
func (r *PostgresMFARepository) SaveBackupCodes(ctx context.Context, tenantID uuid.UUID, userID string, codes []domain.BackupCode) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Remove existing unused codes.
	_, err = tx.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE user_id = $1 AND tenant_id = $2 AND used = FALSE`, userID, tenantID)
	if err != nil {
		return fmt.Errorf("delete old backup codes: %w", err)
	}

	// Insert new codes.
	for _, c := range codes {
		_, err = tx.Exec(ctx,
			`INSERT INTO mfa_backup_codes (id, tenant_id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4, $5)`,
			c.ID, c.TenantID, c.UserID, c.CodeHash, c.CreatedAt,
		)
		if err != nil {
			return fmt.Errorf("insert backup code: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit backup codes: %w", err)
	}

	return nil
}

// GetBackupCodes returns all backup codes for a user.
func (r *PostgresMFARepository) GetBackupCodes(ctx context.Context, tenantID uuid.UUID, userID string) ([]domain.BackupCode, error) {
	query := `
		SELECT id, tenant_id, user_id, code_hash, used, used_at, created_at
		FROM mfa_backup_codes
		WHERE user_id = $1 AND tenant_id = $2
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID, tenantID)
	if err != nil {
		return nil, fmt.Errorf("get backup codes: %w", err)
	}
	defer rows.Close()

	var codes []domain.BackupCode
	for rows.Next() {
		var c domain.BackupCode
		if err := rows.Scan(&c.ID, &c.TenantID, &c.UserID, &c.CodeHash, &c.Used, &c.UsedAt, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan backup code: %w", err)
		}
		codes = append(codes, c)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate backup codes: %w", err)
	}

	return codes, nil
}

// ConsumeBackupCode marks a single unused backup code as used.
func (r *PostgresMFARepository) ConsumeBackupCode(ctx context.Context, tenantID uuid.UUID, userID, codeHash string) error {
	now := time.Now().UTC()
	query := `
		UPDATE mfa_backup_codes
		SET used = TRUE, used_at = $1
		WHERE user_id = $2 AND tenant_id = $3 AND code_hash = $4 AND used = FALSE`

	tag, err := r.pool.Exec(ctx, query, now, userID, tenantID, codeHash)
	if err != nil {
		return fmt.Errorf("consume backup code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("backup code for user %s: %w", userID, ErrNotFound)
	}

	return nil
}

// GetMFAStatus returns the MFA enrollment status for a user.
func (r *PostgresMFARepository) GetMFAStatus(ctx context.Context, tenantID uuid.UUID, userID string) (*domain.MFAStatus, error) {
	status := &domain.MFAStatus{UserID: userID}

	// Check for active secret.
	var mfaType string
	var confirmed bool
	err := r.pool.QueryRow(ctx,
		`SELECT type, confirmed FROM mfa_secrets WHERE user_id = $1 AND tenant_id = $2 AND deleted_at IS NULL`,
		userID, tenantID,
	).Scan(&mfaType, &confirmed)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("get mfa status: %w", err)
	}
	if err == nil {
		status.Type = mfaType
		status.Confirmed = confirmed
		status.Enabled = confirmed
	}

	// Count remaining backup codes.
	err = r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND tenant_id = $2 AND used = FALSE`,
		userID, tenantID,
	).Scan(&status.BackupLeft)
	if err != nil {
		return nil, fmt.Errorf("count backup codes: %w", err)
	}

	return status, nil
}
