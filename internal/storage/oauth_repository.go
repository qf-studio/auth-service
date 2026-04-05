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

// OAuthAccountRepository defines persistence operations for OAuth linked accounts.
type OAuthAccountRepository interface {
	// Create inserts a new OAuth account link.
	// Returns ErrDuplicateOAuthAccount if the provider+provider_user_id pair already exists.
	Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error)

	// FindByProviderAndProviderUserID looks up a linked account.
	// Returns ErrNotFound if no matching record exists.
	FindByProviderAndProviderUserID(ctx context.Context, provider domain.OAuthProviderType, providerUserID string) (*domain.OAuthAccount, error)

	// FindByUserID returns all OAuth accounts linked to a given user.
	FindByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error)

	// Delete removes an OAuth account link by ID.
	// Returns ErrNotFound if the record does not exist.
	Delete(ctx context.Context, id string) error
}

// PostgresOAuthAccountRepository implements OAuthAccountRepository using pgx.
type PostgresOAuthAccountRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresOAuthAccountRepository creates a new PostgreSQL-backed OAuth account repository.
func NewPostgresOAuthAccountRepository(pool *pgxpool.Pool) *PostgresOAuthAccountRepository {
	return &PostgresOAuthAccountRepository{pool: pool}
}

// Create inserts a new OAuth account link.
func (r *PostgresOAuthAccountRepository) Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	query := `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, provider, provider_user_id, email, created_at, updated_at`

	out := &domain.OAuthAccount{}
	err := r.pool.QueryRow(ctx, query,
		account.ID, account.UserID, string(account.Provider),
		account.ProviderUserID, account.Email,
		account.CreatedAt, account.UpdatedAt,
	).Scan(
		&out.ID, &out.UserID, &out.Provider,
		&out.ProviderUserID, &out.Email,
		&out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("provider %s user %s: %w", account.Provider, account.ProviderUserID, ErrDuplicateOAuthAccount)
		}
		return nil, fmt.Errorf("insert oauth account: %w", err)
	}
	return out, nil
}

// FindByProviderAndProviderUserID looks up a linked account by provider and external user ID.
func (r *PostgresOAuthAccountRepository) FindByProviderAndProviderUserID(ctx context.Context, provider domain.OAuthProviderType, providerUserID string) (*domain.OAuthAccount, error) {
	query := `
		SELECT id, user_id, provider, provider_user_id, email, created_at, updated_at
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2`

	out := &domain.OAuthAccount{}
	err := r.pool.QueryRow(ctx, query, string(provider), providerUserID).Scan(
		&out.ID, &out.UserID, &out.Provider,
		&out.ProviderUserID, &out.Email,
		&out.CreatedAt, &out.UpdatedAt,
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
		SELECT id, user_id, provider, provider_user_id, email, created_at, updated_at
		FROM oauth_accounts
		WHERE user_id = $1
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("query oauth accounts: %w", err)
	}
	defer rows.Close()

	var accounts []domain.OAuthAccount
	for rows.Next() {
		var a domain.OAuthAccount
		if err := rows.Scan(
			&a.ID, &a.UserID, &a.Provider,
			&a.ProviderUserID, &a.Email,
			&a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan oauth account: %w", err)
		}
		accounts = append(accounts, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate oauth accounts: %w", err)
	}

	return accounts, nil
}

// Delete removes an OAuth account link by ID.
func (r *PostgresOAuthAccountRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM oauth_accounts WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete oauth account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("oauth account %s: %w", id, ErrNotFound)
	}
	return nil
}
