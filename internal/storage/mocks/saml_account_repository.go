package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockSAMLAccountRepository is a configurable mock for storage.SAMLAccountRepository.
type MockSAMLAccountRepository struct {
	CreateFn          func(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error)
	FindByIDFn        func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.SAMLAccount, error)
	FindByIdPAndNameIDFn func(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID, nameID string) (*domain.SAMLAccount, error)
	ListByUserIDFn    func(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]*domain.SAMLAccount, error)
	ListByIdPIDFn     func(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) ([]*domain.SAMLAccount, error)
	UpdateFn          func(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error)
	DeleteFn          func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// Create delegates to CreateFn.
func (m *MockSAMLAccountRepository) Create(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error) {
	return m.CreateFn(ctx, acct)
}

// FindByID delegates to FindByIDFn.
func (m *MockSAMLAccountRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.SAMLAccount, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// FindByIdPAndNameID delegates to FindByIdPAndNameIDFn.
func (m *MockSAMLAccountRepository) FindByIdPAndNameID(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID, nameID string) (*domain.SAMLAccount, error) {
	return m.FindByIdPAndNameIDFn(ctx, tenantID, idpID, nameID)
}

// ListByUserID delegates to ListByUserIDFn.
func (m *MockSAMLAccountRepository) ListByUserID(ctx context.Context, tenantID uuid.UUID, userID uuid.UUID) ([]*domain.SAMLAccount, error) {
	return m.ListByUserIDFn(ctx, tenantID, userID)
}

// ListByIdPID delegates to ListByIdPIDFn.
func (m *MockSAMLAccountRepository) ListByIdPID(ctx context.Context, tenantID uuid.UUID, idpID uuid.UUID) ([]*domain.SAMLAccount, error) {
	return m.ListByIdPIDFn(ctx, tenantID, idpID)
}

// Update delegates to UpdateFn.
func (m *MockSAMLAccountRepository) Update(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error) {
	return m.UpdateFn(ctx, acct)
}

// Delete delegates to DeleteFn.
func (m *MockSAMLAccountRepository) Delete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.DeleteFn(ctx, tenantID, id)
}
