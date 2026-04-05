package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OAuthAccountRepository defines the persistence operations for linked OAuth identities.
type OAuthAccountRepository interface {
	// Create persists a new OAuth account link.
	// Returns ErrDuplicateOAuthAccount if the provider+provider_user_id pair already exists.
	Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error)

	// FindByProviderAndProviderUserID looks up a linked account by provider and external ID.
	// Returns ErrNotFound if no matching account exists.
	FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error)

	// FindByUserID returns all OAuth accounts linked to a user.
	// Returns an empty slice (not an error) when the user has no linked accounts.
	FindByUserID(ctx context.Context, userID string) ([]*domain.OAuthAccount, error)

	// Delete removes an OAuth account link by its ID.
	// Returns ErrNotFound if no account with that ID exists.
	Delete(ctx context.Context, id string) error
}
