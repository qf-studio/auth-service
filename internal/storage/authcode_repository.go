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

// AuthorizationCodeRepository defines persistence operations for OAuth2 authorization codes.
type AuthorizationCodeRepository interface {
	// Create stores a new authorization code.
	Create(ctx context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error)
	// FindByCodeHash retrieves an authorization code by its hash.
	FindByCodeHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)
	// MarkUsed marks an authorization code as consumed. Returns ErrAuthorizationCodeUsed
	// if the code was already consumed, or ErrAuthorizationCodeExpired if it has expired.
	MarkUsed(ctx context.Context, id uuid.UUID) error
	// DeleteExpired removes authorization codes that expired before the given cutoff.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// PostgresAuthorizationCodeRepository implements AuthorizationCodeRepository using PostgreSQL.
type PostgresAuthorizationCodeRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuthorizationCodeRepository creates a new PostgreSQL-backed authorization code repository.
func NewPostgresAuthorizationCodeRepository(pool *pgxpool.Pool) *PostgresAuthorizationCodeRepository {
	return &PostgresAuthorizationCodeRepository{pool: pool}
}

const authCodeColumns = `id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, expires_at, used_at, created_at`

func scanAuthCode(row pgx.Row) (*domain.AuthorizationCode, error) {
	ac := &domain.AuthorizationCode{}
	err := row.Scan(
		&ac.ID, &ac.CodeHash, &ac.ClientID, &ac.UserID,
		&ac.RedirectURI, &ac.Scopes, &ac.CodeChallenge,
		&ac.CodeChallengeMethod, &ac.Nonce, &ac.ExpiresAt,
		&ac.UsedAt, &ac.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return ac, nil
}

// Create stores a new authorization code.
func (r *PostgresAuthorizationCodeRepository) Create(ctx context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error) {
	query := fmt.Sprintf(`
		INSERT INTO authorization_codes (id, code_hash, client_id, user_id, redirect_uri, scopes, code_challenge, code_challenge_method, nonce, expires_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING %s`, authCodeColumns)

	ac, err := scanAuthCode(r.pool.QueryRow(ctx, query,
		code.ID, code.CodeHash, code.ClientID, code.UserID,
		code.RedirectURI, code.Scopes, code.CodeChallenge,
		code.CodeChallengeMethod, code.Nonce, code.ExpiresAt,
		code.CreatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("authorization code: %w", ErrDuplicateAuthorizationCode)
		}
		return nil, fmt.Errorf("insert authorization code: %w", err)
	}
	return ac, nil
}

// FindByCodeHash retrieves an authorization code by its hash.
func (r *PostgresAuthorizationCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	query := fmt.Sprintf(`SELECT %s FROM authorization_codes WHERE code_hash = $1`, authCodeColumns)
	ac, err := scanAuthCode(r.pool.QueryRow(ctx, query, codeHash))
	if err != nil {
		return nil, fmt.Errorf("find authorization code: %w", err)
	}
	return ac, nil
}

// MarkUsed marks an authorization code as consumed.
func (r *PostgresAuthorizationCodeRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	now := time.Now().UTC()

	// First check current state to return specific errors.
	var usedAt *time.Time
	var expiresAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT used_at, expires_at FROM authorization_codes WHERE id = $1`, id,
	).Scan(&usedAt, &expiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("authorization code %s: %w", id, ErrNotFound)
		}
		return fmt.Errorf("check authorization code state: %w", err)
	}

	if usedAt != nil {
		return fmt.Errorf("authorization code %s: %w", id, ErrAuthorizationCodeUsed)
	}
	if now.After(expiresAt) {
		return fmt.Errorf("authorization code %s: %w", id, ErrAuthorizationCodeExpired)
	}

	tag, err := r.pool.Exec(ctx,
		`UPDATE authorization_codes SET used_at = $1 WHERE id = $2 AND used_at IS NULL`,
		now, id,
	)
	if err != nil {
		return fmt.Errorf("mark authorization code used: %w", err)
	}
	if tag.RowsAffected() == 0 {
		// Race condition: another request consumed it between check and update.
		return fmt.Errorf("authorization code %s: %w", id, ErrAuthorizationCodeUsed)
	}
	return nil
}

// DeleteExpired removes authorization codes that expired before the given cutoff.
func (r *PostgresAuthorizationCodeRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM authorization_codes WHERE expires_at < $1`, before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired authorization codes: %w", err)
	}
	return tag.RowsAffected(), nil
}
