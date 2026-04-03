package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockAdminUserRepository is a configurable mock for storage.AdminUserRepository.
type MockAdminUserRepository struct {
	ListFn       func(ctx context.Context, limit, offset int, status string) ([]*domain.User, int, error)
	FindByIDFn   func(ctx context.Context, id string) (*domain.User, error)
	CreateFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateFn     func(ctx context.Context, user *domain.User) (*domain.User, error)
	SoftDeleteFn func(ctx context.Context, id string) error
	LockFn       func(ctx context.Context, id, reason string) (*domain.User, error)
	UnlockFn     func(ctx context.Context, id string) (*domain.User, error)
}

// List delegates to ListFn.
func (m *MockAdminUserRepository) List(ctx context.Context, limit, offset int, status string) ([]*domain.User, int, error) {
	return m.ListFn(ctx, limit, offset, status)
}

// FindByID delegates to FindByIDFn.
func (m *MockAdminUserRepository) FindByID(ctx context.Context, id string) (*domain.User, error) {
	return m.FindByIDFn(ctx, id)
}

// Create delegates to CreateFn.
func (m *MockAdminUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	return m.CreateFn(ctx, user)
}

// Update delegates to UpdateFn.
func (m *MockAdminUserRepository) Update(ctx context.Context, user *domain.User) (*domain.User, error) {
	return m.UpdateFn(ctx, user)
}

// SoftDelete delegates to SoftDeleteFn.
func (m *MockAdminUserRepository) SoftDelete(ctx context.Context, id string) error {
	return m.SoftDeleteFn(ctx, id)
}

// Lock delegates to LockFn.
func (m *MockAdminUserRepository) Lock(ctx context.Context, id, reason string) (*domain.User, error) {
	return m.LockFn(ctx, id, reason)
}

// Unlock delegates to UnlockFn.
func (m *MockAdminUserRepository) Unlock(ctx context.Context, id string) (*domain.User, error) {
	return m.UnlockFn(ctx, id)
}
