package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockRARRepository is a configurable mock for storage.RARRepository.
type MockRARRepository struct {
	CreateResourceTypeFn     func(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error)
	FindResourceTypeByIDFn   func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.RARResourceType, error)
	FindResourceTypeByTypeFn func(ctx context.Context, tenantID uuid.UUID, typeName string) (*domain.RARResourceType, error)
	ListResourceTypesFn      func(ctx context.Context, tenantID uuid.UUID) ([]*domain.RARResourceType, error)
	UpdateResourceTypeFn     func(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error)
	DeleteResourceTypeFn     func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	AllowClientTypeFn        func(ctx context.Context, tenantID uuid.UUID, clientID, resourceTypeID uuid.UUID) error
	RevokeClientTypeFn       func(ctx context.Context, tenantID uuid.UUID, clientID, resourceTypeID uuid.UUID) error
	ListClientAllowedTypesFn func(ctx context.Context, tenantID uuid.UUID, clientID uuid.UUID) ([]*domain.RARResourceType, error)
	IsClientTypeAllowedFn    func(ctx context.Context, tenantID uuid.UUID, clientID uuid.UUID, typeName string) (bool, error)
}

// CreateResourceType delegates to CreateResourceTypeFn.
func (m *MockRARRepository) CreateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error) {
	return m.CreateResourceTypeFn(ctx, rt)
}

// FindResourceTypeByID delegates to FindResourceTypeByIDFn.
func (m *MockRARRepository) FindResourceTypeByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.RARResourceType, error) {
	return m.FindResourceTypeByIDFn(ctx, tenantID, id)
}

// FindResourceTypeByType delegates to FindResourceTypeByTypeFn.
func (m *MockRARRepository) FindResourceTypeByType(ctx context.Context, tenantID uuid.UUID, typeName string) (*domain.RARResourceType, error) {
	return m.FindResourceTypeByTypeFn(ctx, tenantID, typeName)
}

// ListResourceTypes delegates to ListResourceTypesFn.
func (m *MockRARRepository) ListResourceTypes(ctx context.Context, tenantID uuid.UUID) ([]*domain.RARResourceType, error) {
	return m.ListResourceTypesFn(ctx, tenantID)
}

// UpdateResourceType delegates to UpdateResourceTypeFn.
func (m *MockRARRepository) UpdateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error) {
	return m.UpdateResourceTypeFn(ctx, rt)
}

// DeleteResourceType delegates to DeleteResourceTypeFn.
func (m *MockRARRepository) DeleteResourceType(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.DeleteResourceTypeFn(ctx, tenantID, id)
}

// AllowClientType delegates to AllowClientTypeFn.
func (m *MockRARRepository) AllowClientType(ctx context.Context, tenantID uuid.UUID, clientID, resourceTypeID uuid.UUID) error {
	return m.AllowClientTypeFn(ctx, tenantID, clientID, resourceTypeID)
}

// RevokeClientType delegates to RevokeClientTypeFn.
func (m *MockRARRepository) RevokeClientType(ctx context.Context, tenantID uuid.UUID, clientID, resourceTypeID uuid.UUID) error {
	return m.RevokeClientTypeFn(ctx, tenantID, clientID, resourceTypeID)
}

// ListClientAllowedTypes delegates to ListClientAllowedTypesFn.
func (m *MockRARRepository) ListClientAllowedTypes(ctx context.Context, tenantID uuid.UUID, clientID uuid.UUID) ([]*domain.RARResourceType, error) {
	return m.ListClientAllowedTypesFn(ctx, tenantID, clientID)
}

// IsClientTypeAllowed delegates to IsClientTypeAllowedFn.
func (m *MockRARRepository) IsClientTypeAllowed(ctx context.Context, tenantID uuid.UUID, clientID uuid.UUID, typeName string) (bool, error) {
	return m.IsClientTypeAllowedFn(ctx, tenantID, clientID, typeName)
}
