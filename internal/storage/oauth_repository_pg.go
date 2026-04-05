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

// oauthAccountColumns lists the columns returned by oauth_accounts queries.
const oauthAccountColumns = `id, user_id, provider, provider_user_id, email, created_at`

// PostgresOAuthAccountRepository implements OAuthAccountRepository using pgx against PostgreSQL.
type PostgresOAuthAccountRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresOAuthAccountRepository creates a new PostgreSQL-backed OAuth account repository.
func NewPostgresOAuthAccountRepository(pool *pgxpool.Pool) *PostgresOAuthAccountRepository {
	return &PostgresOAuthAccountRepository{pool: pool}
}

// scanOAuthAccount scans a single row into a domain.OAuthAccount.
func scanOAuthAccount(row pgx.Row) (*domain.OAuthAccount, error) {
	a := &domain.OAuthAccount{}
	err := row.Scan(&a.ID, &a.UserID, &a.Provider, &a.ProviderUserID, &a.Email, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return a, nil
}

// Create stores a new OAuth account link. Returns ErrDuplicateOAuthAccount if the
// provider+provider_user_id combination already exists.
func (r *PostgresOAuthAccountRepository) Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	query := fmt.Sprintf(`
		INSERT INTO oauth_accounts (id, user_id, provider, provider_user_id, email, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, oauthAccountColumns)

	out, err := scanOAuthAccount(r.pool.QueryRow(ctx, query,
		account.ID, account.UserID, account.Provider,
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

// FindByProviderAndProviderUserID returns the OAuth account for a given provider and provider user ID.
// Returns ErrNotFound if no matching account exists.
func (r *PostgresOAuthAccountRepository) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM oauth_accounts WHERE provider = $1 AND provider_user_id = $2`, oauthAccountColumns)

	out, err := scanOAuthAccount(r.pool.QueryRow(ctx, query, provider, providerUserID))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("provider %s user %s: %w", provider, providerUserID, ErrNotFound)
		}
		return nil, fmt.Errorf("find oauth account: %w", err)
	}
	return out, nil
}

// FindByUserID returns all OAuth accounts linked to a user.
func (r *PostgresOAuthAccountRepository) FindByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM oauth_accounts WHERE user_id = $1 ORDER BY created_at`, oauthAccountColumns)

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("find oauth accounts for user %s: %w", userID, err)
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
// Returns ErrNotFound if no matching account exists.
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
