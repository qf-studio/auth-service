package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OAuthAccountRepository defines persistence operations for linked OAuth identities.
type OAuthAccountRepository interface {
	// Create inserts a new OAuth account link.
	// Returns ErrDuplicateOAuthAccount if the provider+provider_user_id pair already exists.
	Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error)

	// FindByProviderAndProviderUserID looks up an OAuth account by provider identity.
	// Returns ErrNotFound if no matching record exists.
	FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error)

	// FindByUserID returns all OAuth accounts linked to the given user.
	FindByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error)

	// DeleteByUserIDAndProvider removes an OAuth account link for a user and provider.
	// Returns ErrNotFound if no matching record exists.
	DeleteByUserIDAndProvider(ctx context.Context, userID, provider string) error
}
