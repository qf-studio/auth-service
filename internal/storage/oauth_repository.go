package storage

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OAuthAccountRepository defines the persistence operations for linked OAuth accounts.
type OAuthAccountRepository interface {
	// Create stores a new OAuth account link.
	Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error)

	// FindByProviderAndProviderUserID returns the OAuth account for a given provider and provider user ID.
	// Returns ErrNotFound if no matching account exists.
	FindByProviderAndProviderUserID(ctx context.Context, tenantID uuid.UUID, provider, providerUserID string) (*domain.OAuthAccount, error)

	// FindByUserID returns all OAuth accounts linked to a user.
	FindByUserID(ctx context.Context, tenantID uuid.UUID, userID string) ([]domain.OAuthAccount, error)

	// Delete removes the OAuth account link for a user and provider.
	// Returns ErrNotFound if no matching account exists.
	Delete(ctx context.Context, tenantID uuid.UUID, userID, provider string) error
}
