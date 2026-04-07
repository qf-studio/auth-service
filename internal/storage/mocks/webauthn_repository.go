package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockWebAuthnCredentialRepository is a configurable mock for storage.WebAuthnCredentialRepository.
type MockWebAuthnCredentialRepository struct {
	CreateCredentialFn             func(ctx context.Context, cred *domain.WebAuthnCredential) error
	GetCredentialsByUserFn         func(ctx context.Context, tenantID uuid.UUID, userID string) ([]domain.WebAuthnCredential, error)
	GetCredentialByCredentialIDFn  func(ctx context.Context, tenantID uuid.UUID, credentialID []byte) (*domain.WebAuthnCredential, error)
	UpdateSignCountFn              func(ctx context.Context, tenantID uuid.UUID, credentialID []byte, signCount uint32, cloneWarning bool) error
	DeleteCredentialFn             func(ctx context.Context, tenantID uuid.UUID, id string) error
}

// CreateCredential delegates to CreateCredentialFn.
func (m *MockWebAuthnCredentialRepository) CreateCredential(ctx context.Context, cred *domain.WebAuthnCredential) error {
	return m.CreateCredentialFn(ctx, cred)
}

// GetCredentialsByUser delegates to GetCredentialsByUserFn.
func (m *MockWebAuthnCredentialRepository) GetCredentialsByUser(ctx context.Context, tenantID uuid.UUID, userID string) ([]domain.WebAuthnCredential, error) {
	return m.GetCredentialsByUserFn(ctx, tenantID, userID)
}

// GetCredentialByCredentialID delegates to GetCredentialByCredentialIDFn.
func (m *MockWebAuthnCredentialRepository) GetCredentialByCredentialID(ctx context.Context, tenantID uuid.UUID, credentialID []byte) (*domain.WebAuthnCredential, error) {
	return m.GetCredentialByCredentialIDFn(ctx, tenantID, credentialID)
}

// UpdateSignCount delegates to UpdateSignCountFn.
func (m *MockWebAuthnCredentialRepository) UpdateSignCount(ctx context.Context, tenantID uuid.UUID, credentialID []byte, signCount uint32, cloneWarning bool) error {
	return m.UpdateSignCountFn(ctx, tenantID, credentialID, signCount, cloneWarning)
}

// DeleteCredential delegates to DeleteCredentialFn.
func (m *MockWebAuthnCredentialRepository) DeleteCredential(ctx context.Context, tenantID uuid.UUID, id string) error {
	return m.DeleteCredentialFn(ctx, tenantID, id)
}
