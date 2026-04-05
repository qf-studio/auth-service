package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// setupOAuthTest returns a pool, UserRepository, and OAuthAccountRepository ready for testing.
// The oauth_accounts table is created and truncated before returning.
func setupOAuthTest(t *testing.T) (*pgxpool.Pool, *storage.PostgresUserRepository, *storage.PostgresOAuthAccountRepository) {
	t.Helper()

	pool := testPool(t) // creates base tables (users, tokens, clients, mfa) and truncates them
	ctx := context.Background()

	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS oauth_accounts (
			id               TEXT        PRIMARY KEY,
			user_id          TEXT        NOT NULL REFERENCES users (id),
			provider         TEXT        NOT NULL,
			provider_user_id TEXT        NOT NULL,
			email            TEXT        NOT NULL DEFAULT '',
			created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
		);
		CREATE UNIQUE INDEX IF NOT EXISTS idx_oauth_accounts_provider_user
			ON oauth_accounts (provider, provider_user_id);
		CREATE INDEX IF NOT EXISTS idx_oauth_accounts_user_id ON oauth_accounts (user_id);
	`)
	require.NoError(t, err)

	_, err = pool.Exec(ctx, `TRUNCATE oauth_accounts`)
	require.NoError(t, err)

	return pool, storage.NewPostgresUserRepository(pool), storage.NewPostgresOAuthAccountRepository(pool)
}

// newTestOAuthAccount builds a test OAuthAccount linked to the given user.
func newTestOAuthAccount(userID string, provider domain.OAuthProvider, providerUserID string) *domain.OAuthAccount {
	return &domain.OAuthAccount{
		ID:             uuid.New().String(),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: providerUserID,
		Email:          providerUserID + "@provider.test",
		CreatedAt:      time.Now().UTC().Truncate(time.Microsecond),
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Create
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresOAuthAccountRepository_Create(t *testing.T) {
	_, userRepo, repo := setupOAuthTest(t)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	tests := []struct {
		name           string
		provider       domain.OAuthProvider
		providerUserID string
	}{
		{
			name:           "google account",
			provider:       domain.OAuthProviderGoogle,
			providerUserID: "google-uid-create-1",
		},
		{
			name:           "github account",
			provider:       domain.OAuthProviderGitHub,
			providerUserID: "github-uid-create-1",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			account := newTestOAuthAccount(user.ID, tc.provider, tc.providerUserID)
			created, err := repo.Create(ctx, account)
			require.NoError(t, err)
			assert.Equal(t, account.ID, created.ID)
			assert.Equal(t, account.UserID, created.UserID)
			assert.Equal(t, account.Provider, created.Provider)
			assert.Equal(t, account.ProviderUserID, created.ProviderUserID)
			assert.Equal(t, account.Email, created.Email)
		})
	}
}

func TestPostgresOAuthAccountRepository_Create_DuplicateProviderUser(t *testing.T) {
	_, userRepo, repo := setupOAuthTest(t)
	ctx := context.Background()

	user1 := newTestUser()
	_, err := userRepo.Create(ctx, user1)
	require.NoError(t, err)

	user2 := newTestUser()
	_, err = userRepo.Create(ctx, user2)
	require.NoError(t, err)

	tests := []struct {
		name            string
		first           *domain.OAuthAccount
		second          *domain.OAuthAccount
		wantSecondError error
	}{
		{
			name:            "same provider and provider_user_id on different users",
			first:           newTestOAuthAccount(user1.ID, domain.OAuthProviderGoogle, "dup-google-uid-1"),
			second:          newTestOAuthAccount(user2.ID, domain.OAuthProviderGoogle, "dup-google-uid-1"),
			wantSecondError: storage.ErrDuplicateOAuthAccount,
		},
		{
			name:            "same user different provider_user_id is allowed",
			first:           newTestOAuthAccount(user1.ID, domain.OAuthProviderGitHub, "gh-uid-distinct-a"),
			second:          newTestOAuthAccount(user1.ID, domain.OAuthProviderGitHub, "gh-uid-distinct-b"),
			wantSecondError: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := repo.Create(ctx, tc.first)
			require.NoError(t, err)

			_, err = repo.Create(ctx, tc.second)
			if tc.wantSecondError != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantSecondError)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// FindByProviderAndProviderUserID
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresOAuthAccountRepository_FindByProviderAndProviderUserID(t *testing.T) {
	_, userRepo, repo := setupOAuthTest(t)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	account := newTestOAuthAccount(user.ID, domain.OAuthProviderGoogle, "fbp-google-uid")
	_, err = repo.Create(ctx, account)
	require.NoError(t, err)

	tests := []struct {
		name           string
		provider       string
		providerUserID string
		wantID         string
		wantErr        error
	}{
		{
			name:           "found",
			provider:       "google",
			providerUserID: "fbp-google-uid",
			wantID:         account.ID,
		},
		{
			name:           "wrong provider",
			provider:       "github",
			providerUserID: "fbp-google-uid",
			wantErr:        storage.ErrNotFound,
		},
		{
			name:           "wrong provider_user_id",
			provider:       "google",
			providerUserID: "nonexistent-uid",
			wantErr:        storage.ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := repo.FindByProviderAndProviderUserID(ctx, tc.provider, tc.providerUserID)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantID, got.ID)
			assert.Equal(t, domain.OAuthProvider(tc.provider), got.Provider)
			assert.Equal(t, tc.providerUserID, got.ProviderUserID)
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// FindByUserID
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresOAuthAccountRepository_FindByUserID(t *testing.T) {
	_, userRepo, repo := setupOAuthTest(t)
	ctx := context.Background()

	userWithAccounts := newTestUser()
	_, err := userRepo.Create(ctx, userWithAccounts)
	require.NoError(t, err)

	userWithoutAccounts := newTestUser()
	_, err = userRepo.Create(ctx, userWithoutAccounts)
	require.NoError(t, err)

	_, err = repo.Create(ctx, newTestOAuthAccount(userWithAccounts.ID, domain.OAuthProviderGoogle, "fbu-google-uid"))
	require.NoError(t, err)
	_, err = repo.Create(ctx, newTestOAuthAccount(userWithAccounts.ID, domain.OAuthProviderGitHub, "fbu-github-uid"))
	require.NoError(t, err)

	tests := []struct {
		name      string
		userID    string
		wantCount int
	}{
		{
			name:      "user with two linked accounts",
			userID:    userWithAccounts.ID,
			wantCount: 2,
		},
		{
			name:      "user with no linked accounts",
			userID:    userWithoutAccounts.ID,
			wantCount: 0,
		},
		{
			name:      "non-existent user returns empty slice",
			userID:    uuid.New().String(),
			wantCount: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			accounts, err := repo.FindByUserID(ctx, tc.userID)
			require.NoError(t, err)
			assert.Len(t, accounts, tc.wantCount)
			for _, a := range accounts {
				assert.Equal(t, tc.userID, a.UserID)
			}
		})
	}
}

// ────────────────────────────────────────────────────────────────────────────
// Delete
// ────────────────────────────────────────────────────────────────────────────

func TestPostgresOAuthAccountRepository_Delete(t *testing.T) {
	_, userRepo, repo := setupOAuthTest(t)
	ctx := context.Background()

	user := newTestUser()
	_, err := userRepo.Create(ctx, user)
	require.NoError(t, err)

	existing := newTestOAuthAccount(user.ID, domain.OAuthProviderGoogle, "del-google-uid")
	_, err = repo.Create(ctx, existing)
	require.NoError(t, err)

	tests := []struct {
		name    string
		id      string
		wantErr error
	}{
		{
			name: "delete existing account",
			id:   existing.ID,
		},
		{
			name:    "delete non-existent account",
			id:      uuid.New().String(),
			wantErr: storage.ErrNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := repo.Delete(ctx, tc.id)
			if tc.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)

			// Verify the account is gone.
			_, err = repo.FindByProviderAndProviderUserID(ctx, string(existing.Provider), existing.ProviderUserID)
			require.Error(t, err)
			assert.ErrorIs(t, err, storage.ErrNotFound)
		})
	}
}
