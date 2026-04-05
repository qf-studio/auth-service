package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockAPIKeyRepository is a configurable mock for storage.APIKeyRepository.
type MockAPIKeyRepository struct {
	CreateFn        func(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	FindByIDFn      func(ctx context.Context, id uuid.UUID) (*domain.APIKey, error)
	FindByHashFn    func(ctx context.Context, keyHash string) (*domain.APIKey, error)
	ListByClientIDFn func(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]*domain.APIKey, int, error)
	UpdateFn        func(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	SoftDeleteFn    func(ctx context.Context, id uuid.UUID) error
	RotateKeyFn     func(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
}

// Create delegates to CreateFn.
func (m *MockAPIKeyRepository) Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	return m.CreateFn(ctx, key)
}

// FindByID delegates to FindByIDFn.
func (m *MockAPIKeyRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.APIKey, error) {
	return m.FindByIDFn(ctx, id)
}

// FindByHash delegates to FindByHashFn.
func (m *MockAPIKeyRepository) FindByHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	return m.FindByHashFn(ctx, keyHash)
}

// ListByClientID delegates to ListByClientIDFn.
func (m *MockAPIKeyRepository) ListByClientID(ctx context.Context, clientID uuid.UUID, limit, offset int) ([]*domain.APIKey, int, error) {
	return m.ListByClientIDFn(ctx, clientID, limit, offset)
}

// Update delegates to UpdateFn.
func (m *MockAPIKeyRepository) Update(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	return m.UpdateFn(ctx, key)
}

// SoftDelete delegates to SoftDeleteFn.
func (m *MockAPIKeyRepository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	return m.SoftDeleteFn(ctx, id)
}

// RotateKey delegates to RotateKeyFn.
func (m *MockAPIKeyRepository) RotateKey(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	return m.RotateKeyFn(ctx, id, newKeyHash, gracePeriodEnds)
}
