package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockClientRepository is a configurable mock for storage.ClientRepository.
type MockClientRepository struct {
	ListFn             func(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error)
	FindByIDFn         func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Client, error)
	FindByNameFn       func(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Client, error)
	CreateFn           func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	UpdateFn           func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	UpdateSecretHashFn func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, secretHash string) error
	RotateSecretFn     func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error
	SoftDeleteFn       func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// List delegates to ListFn.
func (m *MockClientRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error) {
	return m.ListFn(ctx, tenantID, limit, offset, clientType, includeRevoked)
}

// FindByID delegates to FindByIDFn.
func (m *MockClientRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Client, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// FindByName delegates to FindByNameFn.
func (m *MockClientRepository) FindByName(ctx context.Context, tenantID uuid.UUID, name string) (*domain.Client, error) {
	return m.FindByNameFn(ctx, tenantID, name)
}

// Create delegates to CreateFn.
func (m *MockClientRepository) Create(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	return m.CreateFn(ctx, client)
}

// Update delegates to UpdateFn.
func (m *MockClientRepository) Update(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	return m.UpdateFn(ctx, client)
}

// UpdateSecretHash delegates to UpdateSecretHashFn.
func (m *MockClientRepository) UpdateSecretHash(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, secretHash string) error {
	return m.UpdateSecretHashFn(ctx, tenantID, id, secretHash)
}

// RotateSecret delegates to RotateSecretFn.
func (m *MockClientRepository) RotateSecret(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error {
	return m.RotateSecretFn(ctx, tenantID, id, newSecretHash, gracePeriodEnds)
}

// SoftDelete delegates to SoftDeleteFn.
func (m *MockClientRepository) SoftDelete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.SoftDeleteFn(ctx, tenantID, id)
}
