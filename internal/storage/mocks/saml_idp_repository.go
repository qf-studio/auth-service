package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockSAMLIdPRepository is a configurable mock for storage.SAMLIdPRepository.
type MockSAMLIdPRepository struct {
	CreateFn        func(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error)
	FindByIDFn      func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.SAMLIdPConfig, error)
	FindByEntityIDFn func(ctx context.Context, tenantID uuid.UUID, entityID string) (*domain.SAMLIdPConfig, error)
	ListFn          func(ctx context.Context, tenantID uuid.UUID) ([]*domain.SAMLIdPConfig, error)
	UpdateFn        func(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error)
	DeleteFn        func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// Create delegates to CreateFn.
func (m *MockSAMLIdPRepository) Create(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error) {
	return m.CreateFn(ctx, idp)
}

// FindByID delegates to FindByIDFn.
func (m *MockSAMLIdPRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.SAMLIdPConfig, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// FindByEntityID delegates to FindByEntityIDFn.
func (m *MockSAMLIdPRepository) FindByEntityID(ctx context.Context, tenantID uuid.UUID, entityID string) (*domain.SAMLIdPConfig, error) {
	return m.FindByEntityIDFn(ctx, tenantID, entityID)
}

// List delegates to ListFn.
func (m *MockSAMLIdPRepository) List(ctx context.Context, tenantID uuid.UUID) ([]*domain.SAMLIdPConfig, error) {
	return m.ListFn(ctx, tenantID)
}

// Update delegates to UpdateFn.
func (m *MockSAMLIdPRepository) Update(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error) {
	return m.UpdateFn(ctx, idp)
}

// Delete delegates to DeleteFn.
func (m *MockSAMLIdPRepository) Delete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.DeleteFn(ctx, tenantID, id)
}
