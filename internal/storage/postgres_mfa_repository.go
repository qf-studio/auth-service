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

const mfaSecretColumns = `id, user_id, method, secret, confirmed, created_at, updated_at`

func scanMFASecret(row pgx.Row) (*domain.MFASecret, error) {
	s := &domain.MFASecret{}
	err := row.Scan(&s.ID, &s.UserID, &s.Method, &s.Secret, &s.Confirmed, &s.CreatedAt, &s.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return s, nil
}

// PostgresMFARepository implements MFARepository using PostgreSQL.
type PostgresMFARepository struct {
	pool *pgxpool.Pool
}

// NewPostgresMFARepository creates a new PostgreSQL-backed MFA repository.
func NewPostgresMFARepository(pool *pgxpool.Pool) *PostgresMFARepository {
	return &PostgresMFARepository{pool: pool}
}

// SaveSecret creates or replaces the MFA secret for a user+method pair.
func (r *PostgresMFARepository) SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	now := time.Now().UTC()
	if secret.ID == uuid.Nil {
		secret.ID = uuid.New()
	}

	query := fmt.Sprintf(`
		INSERT INTO mfa_secrets (id, user_id, method, secret, confirmed, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (user_id, method)
		DO UPDATE SET secret = EXCLUDED.secret, confirmed = FALSE, updated_at = EXCLUDED.updated_at
		RETURNING %s`, mfaSecretColumns)

	s, err := scanMFASecret(r.pool.QueryRow(ctx, query,
		secret.ID, secret.UserID, secret.Method, secret.Secret,
		false, now, now,
	))
	if err != nil {
		return nil, fmt.Errorf("save mfa secret: %w", err)
	}
	return s, nil
}

// GetSecret retrieves the MFA secret for a user and method.
func (r *PostgresMFARepository) GetSecret(ctx context.Context, userID string, method domain.MFAMethod) (*domain.MFASecret, error) {
	query := fmt.Sprintf(`SELECT %s FROM mfa_secrets WHERE user_id = $1 AND method = $2`, mfaSecretColumns)
	s, err := scanMFASecret(r.pool.QueryRow(ctx, query, userID, method))
	if err != nil {
		return nil, fmt.Errorf("get mfa secret for user %s: %w", userID, err)
	}
	return s, nil
}

// ConfirmSecret marks an MFA secret as confirmed.
func (r *PostgresMFARepository) ConfirmSecret(ctx context.Context, userID string, method domain.MFAMethod) error {
	query := `UPDATE mfa_secrets SET confirmed = TRUE, updated_at = $1 WHERE user_id = $2 AND method = $3 AND confirmed = FALSE`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, userID, method)
	if err != nil {
		return fmt.Errorf("confirm mfa secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Check if it exists at all.
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM mfa_secrets WHERE user_id = $1 AND method = $2)`, userID, method).Scan(&exists)
		if !exists {
			return fmt.Errorf("mfa secret for user %s: %w", userID, ErrNotFound)
		}
		// Already confirmed — idempotent, no error.
		return nil
	}
	return nil
}

// DeleteSecret removes an MFA secret for a user and method.
func (r *PostgresMFARepository) DeleteSecret(ctx context.Context, userID string, method domain.MFAMethod) error {
	query := `DELETE FROM mfa_secrets WHERE user_id = $1 AND method = $2`
	tag, err := r.pool.Exec(ctx, query, userID, method)
	if err != nil {
		return fmt.Errorf("delete mfa secret: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("mfa secret for user %s: %w", userID, ErrNotFound)
	}
	return nil
}

// SaveBackupCodes replaces all backup codes for a user.
func (r *PostgresMFARepository) SaveBackupCodes(ctx context.Context, userID string, codeHashes []string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// Delete existing codes for the user.
	if _, err := tx.Exec(ctx, `DELETE FROM mfa_backup_codes WHERE user_id = $1`, userID); err != nil {
		return fmt.Errorf("delete old backup codes: %w", err)
	}

	now := time.Now().UTC()
	for _, hash := range codeHashes {
		_, err := tx.Exec(ctx,
			`INSERT INTO mfa_backup_codes (id, user_id, code_hash, created_at) VALUES ($1, $2, $3, $4)`,
			uuid.New(), userID, hash, now,
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

// GetBackupCodes returns all unused backup codes for a user.
func (r *PostgresMFARepository) GetBackupCodes(ctx context.Context, userID string) ([]*domain.MFABackupCode, error) {
	query := `SELECT id, user_id, code_hash, used_at, created_at FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL ORDER BY created_at`
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get backup codes: %w", err)
	}
	defer rows.Close()

	var codes []*domain.MFABackupCode
	for rows.Next() {
		c := &domain.MFABackupCode{}
		if err := rows.Scan(&c.ID, &c.UserID, &c.CodeHash, &c.UsedAt, &c.CreatedAt); err != nil {
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
func (r *PostgresMFARepository) ConsumeBackupCode(ctx context.Context, userID string, codeHash string) error {
	query := `
		UPDATE mfa_backup_codes SET used_at = $1
		WHERE id = (
			SELECT id FROM mfa_backup_codes
			WHERE user_id = $2 AND code_hash = $3 AND used_at IS NULL
			LIMIT 1
		)`
	now := time.Now().UTC()

	tag, err := r.pool.Exec(ctx, query, now, userID, codeHash)
	if err != nil {
		return fmt.Errorf("consume backup code: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("backup code for user %s: %w", userID, ErrNotFound)
	}
	return nil
}

// GetMFAStatus returns the aggregate MFA status for a user.
func (r *PostgresMFARepository) GetMFAStatus(ctx context.Context, userID string) (*domain.MFAStatus, error) {
	status := &domain.MFAStatus{}

	// Confirmed methods.
	rows, err := r.pool.Query(ctx,
		`SELECT method FROM mfa_secrets WHERE user_id = $1 AND confirmed = TRUE`, userID)
	if err != nil {
		return nil, fmt.Errorf("get confirmed methods: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var m domain.MFAMethod
		if err := rows.Scan(&m); err != nil {
			return nil, fmt.Errorf("scan method: %w", err)
		}
		status.ConfirmedMethods = append(status.ConfirmedMethods, m)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate methods: %w", err)
	}

	status.Enabled = len(status.ConfirmedMethods) > 0

	// Remaining backup codes.
	err = r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM mfa_backup_codes WHERE user_id = $1 AND used_at IS NULL`, userID,
	).Scan(&status.BackupCodesLeft)
	if err != nil {
		return nil, fmt.Errorf("count backup codes: %w", err)
	}

	return status, nil
}
