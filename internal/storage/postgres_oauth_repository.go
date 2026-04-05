package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// PostgresOAuthAccountRepository implements OAuthAccountRepository using pgx against PostgreSQL.
type PostgresOAuthAccountRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresOAuthAccountRepository creates a new PostgreSQL-backed OAuth account repository.
func NewPostgresOAuthAccountRepository(pool *pgxpool.Pool) *PostgresOAuthAccountRepository {
	return &PostgresOAuthAccountRepository{pool: pool}
}

// Create stores a new OAuth account link.
func (r *PostgresOAuthAccountRepository) Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	query := `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, provider, provider_user_id, email, created_at`

	out := &domain.OAuthAccount{}
	err := r.pool.QueryRow(ctx, query,
		account.ID, account.UserID, account.Provider,
		account.ProviderUserID, account.Email, account.CreatedAt,
	).Scan(
		&out.ID, &out.UserID, &out.Provider,
		&out.ProviderUserID, &out.Email, &out.CreatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("provider %s user %s: %w", account.Provider, account.UserID, ErrDuplicateOAuthAccount)
		}
		return nil, fmt.Errorf("insert oauth account: %w", err)
	}

	return out, nil
}

// FindByProviderAndProviderUserID returns the OAuth account for a given provider and provider user ID.
func (r *PostgresOAuthAccountRepository) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, created_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2`

	out := &domain.OAuthAccount{}
	err := r.pool.QueryRow(ctx, query, provider, providerUserID).Scan(
		&out.ID, &out.UserID, &out.Provider,
		&out.ProviderUserID, &out.Email, &out.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("provider %s user %s: %w", provider, providerUserID, ErrNotFound)
		}
		return nil, fmt.Errorf("find oauth account: %w", err)
	}

	return out, nil
}

// FindByUserID returns all OAuth accounts linked to a user.
func (r *PostgresOAuthAccountRepository) FindByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, created_at
		FROM oauth_accounts
		WHERE user_id = $1
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("find oauth accounts by user: %w", err)
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
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate oauth accounts: %w", err)
	}

	return accounts, nil
}

// Delete removes the OAuth account link for a user and provider.
func (r *PostgresOAuthAccountRepository) Delete(ctx context.Context, userID, provider string) error {
	query := `DELETE FROM oauth_accounts WHERE user_id = $1 AND provider = $2`

	tag, err := r.pool.Exec(ctx, query, userID, provider)
	if err != nil {
		return fmt.Errorf("delete oauth account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s provider %s: %w", userID, provider, ErrNotFound)
	}

	return nil
}
