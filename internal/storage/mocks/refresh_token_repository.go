package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockRefreshTokenRepository is a configurable mock for storage.RefreshTokenRepository.
type MockRefreshTokenRepository struct {
	StoreFn            func(ctx context.Context, tenantID uuid.UUID, signature, userID string, expiresAt time.Time) error
	FindBySignatureFn  func(ctx context.Context, tenantID uuid.UUID, signature string) (*domain.RefreshTokenRecord, error)
	RevokeFn           func(ctx context.Context, tenantID uuid.UUID, signature string) error
	RevokeAllForUserFn func(ctx context.Context, tenantID uuid.UUID, userID string) error
}

// Store delegates to StoreFn.
func (m *MockRefreshTokenRepository) Store(ctx context.Context, tenantID uuid.UUID, signature, userID string, expiresAt time.Time) error {
	return m.StoreFn(ctx, tenantID, signature, userID, expiresAt)
}

// FindBySignature delegates to FindBySignatureFn.
func (m *MockRefreshTokenRepository) FindBySignature(ctx context.Context, tenantID uuid.UUID, signature string) (*domain.RefreshTokenRecord, error) {
	return m.FindBySignatureFn(ctx, tenantID, signature)
}

// Revoke delegates to RevokeFn.
func (m *MockRefreshTokenRepository) Revoke(ctx context.Context, tenantID uuid.UUID, signature string) error {
	return m.RevokeFn(ctx, tenantID, signature)
}

// RevokeAllForUser delegates to RevokeAllForUserFn.
func (m *MockRefreshTokenRepository) RevokeAllForUser(ctx context.Context, tenantID uuid.UUID, userID string) error {
	return m.RevokeAllForUserFn(ctx, tenantID, userID)
}
