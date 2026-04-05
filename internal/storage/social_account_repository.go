package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SocialAccountRepository defines persistence operations for OAuth social accounts.
type SocialAccountRepository interface {
	// FindByProviderUser looks up a social account by provider + provider user ID.
	// Returns ErrNotFound if no match exists.
	FindByProviderUser(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.SocialAccount, error)

	// FindByUserID returns all social accounts linked to a given user.
	FindByUserID(ctx context.Context, userID string) ([]domain.SocialAccount, error)

	// Link creates a new social account record linking a provider identity to a user.
	// Returns ErrDuplicateSocialAccount if the provider+providerUserID pair already exists.
	Link(ctx context.Context, account *domain.SocialAccount) (*domain.SocialAccount, error)
}
