package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockOAuthAccountRepository is a configurable mock for storage.OAuthAccountRepository.
type MockOAuthAccountRepository struct {
	CreateFn                        func(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error)
	FindByProviderAndProviderUserIDFn func(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error)
	FindByUserIDFn                  func(ctx context.Context, userID string) ([]domain.OAuthAccount, error)
	DeleteFn                        func(ctx context.Context, userID, provider string) error
}

// Create delegates to CreateFn.
func (m *MockOAuthAccountRepository) Create(ctx context.Context, account *domain.OAuthAccount) (*domain.OAuthAccount, error) {
	return m.CreateFn(ctx, account)
}

// FindByProviderAndProviderUserID delegates to FindByProviderAndProviderUserIDFn.
func (m *MockOAuthAccountRepository) FindByProviderAndProviderUserID(ctx context.Context, provider, providerUserID string) (*domain.OAuthAccount, error) {
	return m.FindByProviderAndProviderUserIDFn(ctx, provider, providerUserID)
}

// FindByUserID delegates to FindByUserIDFn.
func (m *MockOAuthAccountRepository) FindByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	return m.FindByUserIDFn(ctx, userID)
}

// Delete delegates to DeleteFn.
func (m *MockOAuthAccountRepository) Delete(ctx context.Context, userID, provider string) error {
	return m.DeleteFn(ctx, userID, provider)
}
