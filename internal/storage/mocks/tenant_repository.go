package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockTenantRepository is a configurable mock for storage.TenantRepository.
type MockTenantRepository struct {
	CreateFn     func(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	FindByIDFn   func(ctx context.Context, id uuid.UUID) (*domain.Tenant, error)
	FindBySlugFn func(ctx context.Context, slug string) (*domain.Tenant, error)
	ListFn       func(ctx context.Context, limit, offset int) ([]*domain.Tenant, int, error)
	UpdateFn     func(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	DeleteFn     func(ctx context.Context, id uuid.UUID) error
}

// Create delegates to CreateFn.
func (m *MockTenantRepository) Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	return m.CreateFn(ctx, tenant)
}

// FindByID delegates to FindByIDFn.
func (m *MockTenantRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.Tenant, error) {
	return m.FindByIDFn(ctx, id)
}

// FindBySlug delegates to FindBySlugFn.
func (m *MockTenantRepository) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	return m.FindBySlugFn(ctx, slug)
}

// List delegates to ListFn.
func (m *MockTenantRepository) List(ctx context.Context, limit, offset int) ([]*domain.Tenant, int, error) {
	return m.ListFn(ctx, limit, offset)
}

// Update delegates to UpdateFn.
func (m *MockTenantRepository) Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	return m.UpdateFn(ctx, tenant)
}

// Delete delegates to DeleteFn.
func (m *MockTenantRepository) Delete(ctx context.Context, id uuid.UUID) error {
	return m.DeleteFn(ctx, id)
}
