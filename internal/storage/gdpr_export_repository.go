package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// GDPRExportRepository defines read-only queries for aggregating user data across tables.
type GDPRExportRepository interface {
	// GetUserData retrieves the user record. Returns ErrNotFound if absent.
	GetUserData(ctx context.Context, userID string) (*domain.User, error)

	// GetOAuthAccounts retrieves all OAuth accounts linked to the user.
	GetOAuthAccounts(ctx context.Context, userID string) ([]domain.OAuthAccount, error)

	// GetRefreshTokens retrieves all refresh token records for the user.
	GetRefreshTokens(ctx context.Context, userID string) ([]domain.RefreshTokenRecord, error)

	// GetConsentRecords retrieves all consent records for the user.
	GetConsentRecords(ctx context.Context, userID string) ([]domain.ConsentRecord, error)

	// SoftDeleteUser sets the deleted_at timestamp on the user record.
	SoftDeleteUser(ctx context.Context, userID string) error

	// DeleteOAuthAccounts removes all OAuth account links for a user.
	DeleteOAuthAccounts(ctx context.Context, userID string) error

	// DeleteRefreshTokens removes all refresh tokens for a user.
	DeleteRefreshTokens(ctx context.Context, userID string) error

	// AnonymizeAuditLogs replaces user-identifiable information in audit logs with anonymized values.
	AnonymizeAuditLogs(ctx context.Context, userID string) error

	// DeleteExpiredSoftDeletedUsers permanently deletes users whose deleted_at is older than the given days.
	DeleteExpiredSoftDeletedUsers(ctx context.Context, retentionDays int) (int64, error)

	// DeleteExpiredRefreshTokens removes refresh tokens that expired before the given days.
	DeleteExpiredRefreshTokens(ctx context.Context, retentionDays int) (int64, error)
}

// PostgresGDPRExportRepository implements GDPRExportRepository using pgx.
type PostgresGDPRExportRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresGDPRExportRepository creates a new PostgreSQL-backed GDPR export repository.
func NewPostgresGDPRExportRepository(pool *pgxpool.Pool) *PostgresGDPRExportRepository {
	return &PostgresGDPRExportRepository{pool: pool}
}

// GetUserData retrieves the user record by ID.
func (r *PostgresGDPRExportRepository) GetUserData(ctx context.Context, userID string) (*domain.User, error) {
	query := `SELECT id, email, password_hash, name, roles, locked, locked_at, locked_reason,
		email_verified, email_verify_token, email_verify_token_expires_at,
		last_login_at, created_at, updated_at, deleted_at
		FROM users WHERE id = $1`

	user := &domain.User{}
	err := r.pool.QueryRow(ctx, query, userID).Scan(
		&user.ID, &user.Email, &user.PasswordHash, &user.Name, &user.Roles,
		&user.Locked, &user.LockedAt, &user.LockedReason,
		&user.EmailVerified, &user.EmailVerifyToken, &user.EmailVerifyTokenExpiresAt,
		&user.LastLoginAt, &user.CreatedAt, &user.UpdatedAt, &user.DeletedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("get user data: %w", mapNoRows(err))
	}
	return user, nil
}

// GetOAuthAccounts retrieves all OAuth accounts linked to the user.
func (r *PostgresGDPRExportRepository) GetOAuthAccounts(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := `SELECT id, user_id, provider, provider_user_id, email, created_at
		FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get oauth accounts: %w", err)
	}
	defer rows.Close()

	var accounts []domain.OAuthAccount
	for rows.Next() {
		var a domain.OAuthAccount
		if err := rows.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.Email, &a.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan oauth account: %w", err)
		}
		accounts = append(accounts, a)
	}
	return accounts, rows.Err()
}

// GetRefreshTokens retrieves all refresh token records for the user.
func (r *PostgresGDPRExportRepository) GetRefreshTokens(ctx context.Context, userID string) ([]domain.RefreshTokenRecord, error) {
	query := `SELECT signature, user_id, expires_at, created_at, revoked_at
		FROM refresh_tokens WHERE user_id = $1 ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get refresh tokens: %w", err)
	}
	defer rows.Close()

	var tokens []domain.RefreshTokenRecord
	for rows.Next() {
		var t domain.RefreshTokenRecord
		if err := rows.Scan(&t.Signature, &t.UserID, &t.ExpiresAt, &t.CreatedAt, &t.RevokedAt); err != nil {
			return nil, fmt.Errorf("scan refresh token: %w", err)
		}
		tokens = append(tokens, t)
	}
	return tokens, rows.Err()
}

// GetConsentRecords retrieves all consent records for the user.
func (r *PostgresGDPRExportRepository) GetConsentRecords(ctx context.Context, userID string) ([]domain.ConsentRecord, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_records WHERE user_id = $1 ORDER BY created_at`, consentColumns)

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("get consent records: %w", err)
	}
	defer rows.Close()

	var records []domain.ConsentRecord
	for rows.Next() {
		var rec domain.ConsentRecord
		if err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.ConsentType, &rec.Granted,
			&rec.IPAddress, &rec.UserAgent, &rec.GrantedAt, &rec.RevokedAt, &rec.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan consent record: %w", err)
		}
		records = append(records, rec)
	}
	return records, rows.Err()
}

// SoftDeleteUser sets the deleted_at timestamp on the user record.
func (r *PostgresGDPRExportRepository) SoftDeleteUser(ctx context.Context, userID string) error {
	query := `UPDATE users SET deleted_at = NOW(), updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("soft delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", userID, ErrNotFound)
	}
	return nil
}

// DeleteOAuthAccounts removes all OAuth account links for a user.
func (r *PostgresGDPRExportRepository) DeleteOAuthAccounts(ctx context.Context, userID string) error {
	query := `DELETE FROM oauth_accounts WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete oauth accounts for user %s: %w", userID, err)
	}
	return nil
}

// DeleteRefreshTokens removes all refresh tokens for a user.
func (r *PostgresGDPRExportRepository) DeleteRefreshTokens(ctx context.Context, userID string) error {
	query := `DELETE FROM refresh_tokens WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete refresh tokens for user %s: %w", userID, err)
	}
	return nil
}

// AnonymizeAuditLogs replaces user-identifiable info in audit logs with anonymized placeholders.
func (r *PostgresGDPRExportRepository) AnonymizeAuditLogs(ctx context.Context, userID string) error {
	query := `UPDATE audit_logs SET user_id = 'anonymized', ip_address = '0.0.0.0', user_agent = 'anonymized', updated_at = NOW() WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("anonymize audit logs for user %s: %w", userID, err)
	}
	return nil
}

// DeleteExpiredSoftDeletedUsers permanently deletes users whose deleted_at is older than retentionDays.
func (r *PostgresGDPRExportRepository) DeleteExpiredSoftDeletedUsers(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM users WHERE deleted_at IS NOT NULL AND deleted_at < NOW() - make_interval(days => $1)`

	tag, err := r.pool.Exec(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("delete expired soft-deleted users: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExpiredRefreshTokens removes refresh tokens that expired more than retentionDays ago.
func (r *PostgresGDPRExportRepository) DeleteExpiredRefreshTokens(ctx context.Context, retentionDays int) (int64, error) {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW() - make_interval(days => $1)`

	tag, err := r.pool.Exec(ctx, query, retentionDays)
	if err != nil {
		return 0, fmt.Errorf("delete expired refresh tokens: %w", err)
	}
	return tag.RowsAffected(), nil
}

// mapNoRows converts pgx.ErrNoRows to ErrNotFound.
func mapNoRows(err error) error {
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}
