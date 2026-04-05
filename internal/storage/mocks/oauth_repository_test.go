package mocks_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

func TestMockOAuthAccountRepository_Create(t *testing.T) {
	mock := &mocks.MockOAuthAccountRepository{
		CreateFn: func(_ context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
			account.ID = "generated-id"
			return account, nil
		},
	}

	account := &domain.OAuthAccount{
		UserID:         "user-1",
		Provider:       "google",
		ProviderUserID: "goog-123",
		Email:          "test@example.com",
		CreatedAt:      time.Now().UTC(),
	}

	result, err := mock.Create(context.Background(), account)
	require.NoError(t, err)
	assert.Equal(t, "generated-id", result.ID)
	assert.Equal(t, "google", result.Provider)
}

func TestMockOAuthAccountRepository_FindByProviderAndProviderUserID(t *testing.T) {
	mock := &mocks.MockOAuthAccountRepository{
		FindByProviderAndProviderUserIDFn: func(_ context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
			if provider == "google" && providerUserID == "goog-123" {
				return &domain.OAuthAccount{
					ID:             "oa-1",
					UserID:         "user-1",
					Provider:       provider,
					ProviderUserID: providerUserID,
				}, nil
			}
			return nil, storage.ErrNotFound
		},
	}

	result, err := mock.FindByProviderAndProviderUserID(context.Background(), "google", "goog-123")
	require.NoError(t, err)
	assert.Equal(t, "user-1", result.UserID)

	_, err = mock.FindByProviderAndProviderUserID(context.Background(), "github", "gh-456")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestMockOAuthAccountRepository_FindByUserID(t *testing.T) {
	mock := &mocks.MockOAuthAccountRepository{
		FindByUserIDFn: func(_ context.Context, userID string) ([]domain.OAuthAccount, error) {
			if userID == "user-1" {
				return []domain.OAuthAccount{
					{ID: "oa-1", Provider: "google", UserID: userID},
					{ID: "oa-2", Provider: "github", UserID: userID},
				}, nil
			}
			return nil, nil
		},
	}

	accounts, err := mock.FindByUserID(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Len(t, accounts, 2)

	accounts, err = mock.FindByUserID(context.Background(), "user-999")
	require.NoError(t, err)
	assert.Empty(t, accounts)
}

func TestMockOAuthAccountRepository_Delete(t *testing.T) {
	mock := &mocks.MockOAuthAccountRepository{
		DeleteFn: func(_ context.Context, userID, provider string) error {
			if userID == "user-1" && provider == "google" {
				return nil
			}
			return storage.ErrNotFound
		},
	}

	err := mock.Delete(context.Background(), "user-1", "google")
	require.NoError(t, err)

	err = mock.Delete(context.Background(), "user-1", "apple")
	assert.ErrorIs(t, err, storage.ErrNotFound)
}
