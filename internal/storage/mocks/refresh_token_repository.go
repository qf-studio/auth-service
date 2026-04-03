package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockRefreshTokenRepository is a configurable mock for storage.RefreshTokenRepository.
type MockRefreshTokenRepository struct {
	StoreFn            func(ctx context.Context, signature, userID string, expiresAt time.Time) error
	FindBySignatureFn  func(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)
	RevokeFn           func(ctx context.Context, signature string) error
	RevokeAllForUserFn func(ctx context.Context, userID string) error
}

// Store delegates to StoreFn.
func (m *MockRefreshTokenRepository) Store(ctx context.Context, signature, userID string, expiresAt time.Time) error {
	return m.StoreFn(ctx, signature, userID, expiresAt)
}

// FindBySignature delegates to FindBySignatureFn.
func (m *MockRefreshTokenRepository) FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error) {
	return m.FindBySignatureFn(ctx, signature)
}

// Revoke delegates to RevokeFn.
func (m *MockRefreshTokenRepository) Revoke(ctx context.Context, signature string) error {
	return m.RevokeFn(ctx, signature)
}

// RevokeAllForUser delegates to RevokeAllForUserFn.
func (m *MockRefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	return m.RevokeAllForUserFn(ctx, userID)
}
