package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// MockAdminUserRepository is a configurable mock for storage.AdminUserRepository.
type MockAdminUserRepository struct {
	ListFn           func(ctx context.Context, tenantID uuid.UUID, limit, offset int, status string) ([]*domain.User, int, error)
	SearchUsersFn    func(ctx context.Context, tenantID uuid.UUID, limit, offset int, filter storage.UserSearchFilter) ([]*domain.User, int, error)
	FindByIDFn       func(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
	CreateFn         func(ctx context.Context, user *domain.User) (*domain.User, error)
	UpdateFn         func(ctx context.Context, user *domain.User) (*domain.User, error)
	SoftDeleteFn     func(ctx context.Context, tenantID uuid.UUID, id string) error
	LockFn           func(ctx context.Context, tenantID uuid.UUID, id, reason string) (*domain.User, error)
	UnlockFn         func(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
	BulkUpdateStatFn func(ctx context.Context, tenantID uuid.UUID, ids []string, action string, reason string) (int64, error)
	BulkAssignRoleFn func(ctx context.Context, tenantID uuid.UUID, ids []string, role string) (int64, error)
}

// List delegates to ListFn.
func (m *MockAdminUserRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, status string) ([]*domain.User, int, error) {
	return m.ListFn(ctx, tenantID, limit, offset, status)
}

// FindByID delegates to FindByIDFn.
func (m *MockAdminUserRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	return m.FindByIDFn(ctx, tenantID, id)
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
func (m *MockAdminUserRepository) SoftDelete(ctx context.Context, tenantID uuid.UUID, id string) error {
	return m.SoftDeleteFn(ctx, tenantID, id)
}

// Lock delegates to LockFn.
func (m *MockAdminUserRepository) Lock(ctx context.Context, tenantID uuid.UUID, id, reason string) (*domain.User, error) {
	return m.LockFn(ctx, tenantID, id, reason)
}

// Unlock delegates to UnlockFn.
func (m *MockAdminUserRepository) Unlock(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error) {
	return m.UnlockFn(ctx, tenantID, id)
}

// SearchUsers delegates to SearchUsersFn.
func (m *MockAdminUserRepository) SearchUsers(ctx context.Context, tenantID uuid.UUID, limit, offset int, filter storage.UserSearchFilter) ([]*domain.User, int, error) {
	return m.SearchUsersFn(ctx, tenantID, limit, offset, filter)
}

// BulkUpdateStatus delegates to BulkUpdateStatFn.
func (m *MockAdminUserRepository) BulkUpdateStatus(ctx context.Context, tenantID uuid.UUID, ids []string, action string, reason string) (int64, error) {
	return m.BulkUpdateStatFn(ctx, tenantID, ids, action, reason)
}

// BulkAssignRole delegates to BulkAssignRoleFn.
func (m *MockAdminUserRepository) BulkAssignRole(ctx context.Context, tenantID uuid.UUID, ids []string, role string) (int64, error) {
	return m.BulkAssignRoleFn(ctx, tenantID, ids, role)
}
