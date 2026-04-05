package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockAuthorizationCodeRepository is a configurable mock for storage.AuthorizationCodeRepository.
type MockAuthorizationCodeRepository struct {
	CreateFn       func(ctx context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error)
	FindByCodeHashFn func(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error)
	MarkUsedFn     func(ctx context.Context, id uuid.UUID) error
	DeleteExpiredFn func(ctx context.Context, before time.Time) (int64, error)
}

// Create delegates to CreateFn.
func (m *MockAuthorizationCodeRepository) Create(ctx context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error) {
	return m.CreateFn(ctx, code)
}

// FindByCodeHash delegates to FindByCodeHashFn.
func (m *MockAuthorizationCodeRepository) FindByCodeHash(ctx context.Context, codeHash string) (*domain.AuthorizationCode, error) {
	return m.FindByCodeHashFn(ctx, codeHash)
}

// MarkUsed delegates to MarkUsedFn.
func (m *MockAuthorizationCodeRepository) MarkUsed(ctx context.Context, id uuid.UUID) error {
	return m.MarkUsedFn(ctx, id)
}

// DeleteExpired delegates to DeleteExpiredFn.
func (m *MockAuthorizationCodeRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	return m.DeleteExpiredFn(ctx, before)
}
