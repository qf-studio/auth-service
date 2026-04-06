package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockSAMLIdentityRepository is a configurable mock for storage.SAMLIdentityRepository.
type MockSAMLIdentityRepository struct {
	CreateFn           func(ctx context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error)
	FindByIdPAndNameIDFn func(ctx context.Context, idpEntityID, nameID string) (*domain.SAMLIdentity, error)
	FindByUserIDFn     func(ctx context.Context, userID string) ([]domain.SAMLIdentity, error)
	DeleteFn           func(ctx context.Context, userID, idpEntityID string) error
}

// Create delegates to CreateFn.
func (m *MockSAMLIdentityRepository) Create(ctx context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error) {
	if m.CreateFn != nil {
		return m.CreateFn(ctx, identity)
	}
	return identity, nil
}

// FindByIdPAndNameID delegates to FindByIdPAndNameIDFn.
func (m *MockSAMLIdentityRepository) FindByIdPAndNameID(ctx context.Context, idpEntityID, nameID string) (*domain.SAMLIdentity, error) {
	if m.FindByIdPAndNameIDFn != nil {
		return m.FindByIdPAndNameIDFn(ctx, idpEntityID, nameID)
	}
	return nil, nil
}

// FindByUserID delegates to FindByUserIDFn.
func (m *MockSAMLIdentityRepository) FindByUserID(ctx context.Context, userID string) ([]domain.SAMLIdentity, error) {
	if m.FindByUserIDFn != nil {
		return m.FindByUserIDFn(ctx, userID)
	}
	return nil, nil
}

// Delete delegates to DeleteFn.
func (m *MockSAMLIdentityRepository) Delete(ctx context.Context, userID, idpEntityID string) error {
	if m.DeleteFn != nil {
		return m.DeleteFn(ctx, userID, idpEntityID)
	}
	return nil
}
