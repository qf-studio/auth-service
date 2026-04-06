package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// MockAdminUserRepository is a configurable mock for storage.AdminUserRepository.
type MockAdminUserRepository struct {
	ListFn            func(ctx context.Context, limit, offset int, status string) ([]*domain.User, int, error)
	SearchUsersFn     func(ctx context.Context, limit, offset int, filter storage.UserSearchFilter) ([]*domain.User, int, error)
	FindByIDFn        func(ctx context.Context, id string) (*domain.User, error)
	CreateFn          func(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateFn          func(ctx context.Context, user *domain.User) (*domain.User, error)
	SoftDeleteFn      func(ctx context.Context, id string) error
	LockFn            func(ctx context.Context, id, reason string) (*domain.User, error)
	UnlockFn          func(ctx context.Context, id string) (*domain.User, error)
	BulkUpdateStatFn  func(ctx context.Context, ids []string, action string, reason string) (int64, error)
	BulkAssignRoleFn  func(ctx context.Context, ids []string, role string) (int64, error)
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

// SearchUsers delegates to SearchUsersFn.
func (m *MockAdminUserRepository) SearchUsers(ctx context.Context, limit, offset int, filter storage.UserSearchFilter) ([]*domain.User, int, error) {
	return m.SearchUsersFn(ctx, limit, offset, filter)
}

// BulkUpdateStatus delegates to BulkUpdateStatFn.
func (m *MockAdminUserRepository) BulkUpdateStatus(ctx context.Context, ids []string, action string, reason string) (int64, error) {
	return m.BulkUpdateStatFn(ctx, ids, action, reason)
}

// BulkAssignRole delegates to BulkAssignRoleFn.
func (m *MockAdminUserRepository) BulkAssignRole(ctx context.Context, ids []string, role string) (int64, error) {
	return m.BulkAssignRoleFn(ctx, ids, role)
}
