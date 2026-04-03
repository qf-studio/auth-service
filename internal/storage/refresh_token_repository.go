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

// RefreshTokenRepository defines the persistence operations for refresh tokens.
type RefreshTokenRepository interface {
	// Store persists a new refresh token signature.
	Store(ctx context.Context, signature, userID string, expiresAt time.Time) error

	// FindBySignature retrieves a token record by its signature.
	// Returns ErrNotFound if absent.
	FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)

	// Revoke marks a single refresh token as revoked.
	// Returns ErrNotFound if the signature does not exist.
	Revoke(ctx context.Context, signature string) error

	// RevokeAllForUser marks all non-revoked refresh tokens for a user as revoked.
	RevokeAllForUser(ctx context.Context, userID string) error
}

// PostgresRefreshTokenRepository implements RefreshTokenRepository using pgx.
type PostgresRefreshTokenRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRefreshTokenRepository creates a new PostgreSQL-backed refresh token repository.
func NewPostgresRefreshTokenRepository(pool *pgxpool.Pool) *PostgresRefreshTokenRepository {
	return &PostgresRefreshTokenRepository{pool: pool}
}

// Store inserts a new refresh token record.
func (r *PostgresRefreshTokenRepository) Store(ctx context.Context, signature, userID string, expiresAt time.Time) error {
	query := `
		INSERT INTO refresh_tokens (signature, user_id, expires_at, created_at)
		VALUES ($1, $2, $3, $4)`

	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, query, signature, userID, expiresAt, now)
	if err != nil {
		return fmt.Errorf("store refresh token: %w", err)
	}

	return nil
}

// FindBySignature retrieves a refresh token record by its signature.
func (r *PostgresRefreshTokenRepository) FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error) {
	query := `
		SELECT signature, user_id, expires_at, created_at, revoked_at
		FROM refresh_tokens
		WHERE signature = $1`

	rec := &domain.RefreshTokenRecord{}
	err := r.pool.QueryRow(ctx, query, signature).Scan(
		&rec.Signature, &rec.UserID, &rec.ExpiresAt, &rec.CreatedAt, &rec.RevokedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("signature %s: %w", signature, ErrNotFound)
		}
		return nil, fmt.Errorf("find refresh token: %w", err)
	}

	return rec, nil
}

// Revoke marks a refresh token as revoked by setting revoked_at.
func (r *PostgresRefreshTokenRepository) Revoke(ctx context.Context, signature string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE signature = $2 AND revoked_at IS NULL`

	now := time.Now().UTC()
	tag, err := r.pool.Exec(ctx, query, now, signature)
	if err != nil {
		return fmt.Errorf("revoke refresh token: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("signature %s: %w", signature, ErrNotFound)
	}

	return nil
}

// RevokeAllForUser marks all non-revoked refresh tokens for a user as revoked.
func (r *PostgresRefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	query := `
		UPDATE refresh_tokens
		SET revoked_at = $1
		WHERE user_id = $2 AND revoked_at IS NULL`

	now := time.Now().UTC()
	_, err := r.pool.Exec(ctx, query, now, userID)
	if err != nil {
		return fmt.Errorf("revoke all refresh tokens for user %s: %w", userID, err)
	}

	return nil
}
