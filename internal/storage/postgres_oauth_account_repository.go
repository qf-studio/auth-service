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

const oauthAccountColumns = "id, user_id, provider, provider_user_id, email, created_at"

func scanOAuthAccount(row pgx.Row) (*domain.OAuthAccount, error) {
	out := &domain.OAuthAccount{}
	var provider string
	err := row.Scan(&out.ID, &out.UserID, &provider, &out.ProviderUserID, &out.Email, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	out.Provider = domain.OAuthProvider(provider)
	return out, nil
}

// Create inserts a new OAuth account link and returns the persisted record.
func (r *PostgresOAuthAccountRepository) Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	query := `
		INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING ` + oauthAccountColumns

	out, err := scanOAuthAccount(r.pool.QueryRow(ctx, query,
		account.ID, account.UserID, string(account.Provider),
		account.ProviderUserID, account.Email, account.CreatedAt,
	))
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
func (r *PostgresOAuthAccountRepository) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	query := `
		SELECT ` + oauthAccountColumns + `
		FROM oauth_accounts
		WHERE provider = $1 AND provider_user_id = $2`

	out, err := scanOAuthAccount(r.pool.QueryRow(ctx, query, provider, providerUserID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("provider %s user %s: %w", provider, providerUserID, ErrNotFound)
		}
		return nil, fmt.Errorf("find oauth account by provider: %w", err)
	}

	return out, nil
}

// FindByUserID returns all OAuth accounts linked to the given user.
func (r *PostgresOAuthAccountRepository) FindByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error) {
	query := `
		SELECT ` + oauthAccountColumns + `
		FROM oauth_accounts
		WHERE user_id = $1
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("find oauth accounts by user: %w", err)
	}
	defer rows.Close()

	var accounts []*domain.OAuthAccount
	for rows.Next() {
		account, err := scanOAuthAccount(rows)
		if err != nil {
			return nil, fmt.Errorf("scan oauth account: %w", err)
		}
		accounts = append(accounts, account)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate oauth accounts: %w", err)
	}

	return accounts, nil
}

// Delete removes an OAuth account link by its ID.
func (r *PostgresOAuthAccountRepository) Delete(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM oauth_accounts WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete oauth account: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("oauth account %s: %w", id, ErrNotFound)
	}

	return nil
}
