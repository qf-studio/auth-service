package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockAPIKeyRepository is a configurable mock for storage.APIKeyRepository.
type MockAPIKeyRepository struct {
	ListFn          func(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientID string) ([]*domain.APIKey, int, error)
	FindByIDFn      func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.APIKey, error)
	FindByKeyHashFn func(ctx context.Context, tenantID uuid.UUID, keyHash string) (*domain.APIKey, error)
	CreateFn        func(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	UpdateFn        func(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	RevokeFn        func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	RotateKeyFn     func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
	UpdateLastUsedFn func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// List delegates to ListFn.
func (m *MockAPIKeyRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientID string) ([]*domain.APIKey, int, error) {
	return m.ListFn(ctx, tenantID, limit, offset, clientID)
}

// FindByID delegates to FindByIDFn.
func (m *MockAPIKeyRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.APIKey, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// FindByKeyHash delegates to FindByKeyHashFn.
func (m *MockAPIKeyRepository) FindByKeyHash(ctx context.Context, tenantID uuid.UUID, keyHash string) (*domain.APIKey, error) {
	return m.FindByKeyHashFn(ctx, tenantID, keyHash)
}

// Create delegates to CreateFn.
func (m *MockAPIKeyRepository) Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	return m.CreateFn(ctx, key)
}

// Update delegates to UpdateFn.
func (m *MockAPIKeyRepository) Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	return m.UpdateFn(ctx, key)
}

// Revoke delegates to RevokeFn.
func (m *MockAPIKeyRepository) Revoke(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.RevokeFn(ctx, tenantID, id)
}

// RotateKey delegates to RotateKeyFn.
func (m *MockAPIKeyRepository) RotateKey(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	return m.RotateKeyFn(ctx, tenantID, id, newKeyHash, gracePeriodEnds)
}

// UpdateLastUsed delegates to UpdateLastUsedFn.
func (m *MockAPIKeyRepository) UpdateLastUsed(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.UpdateLastUsedFn(ctx, tenantID, id)
}
