package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockGDPRConsentRepository is a configurable mock for storage.GDPRConsentRepository.
type MockGDPRConsentRepository struct {
	CreateFn              func(ctx context.Context, record *domain.ConsentRecord) (*domain.ConsentRecord, error)
	FindByIDFn            func(ctx context.Context, id string) (*domain.ConsentRecord, error)
	FindByUserIDFn        func(ctx context.Context, userID string) ([]domain.ConsentRecord, error)
	FindByUserIDAndTypeFn func(ctx context.Context, userID, consentType string) (*domain.ConsentRecord, error)
	RevokeFn              func(ctx context.Context, id string, revokedAt time.Time) error
	DeleteByUserIDFn      func(ctx context.Context, userID string) error
}

// Create delegates to CreateFn.
func (m *MockGDPRConsentRepository) Create(ctx context.Context, record *domain.ConsentRecord) (*domain.ConsentRecord, error) {
	return m.CreateFn(ctx, record)
}

// FindByID delegates to FindByIDFn.
func (m *MockGDPRConsentRepository) FindByID(ctx context.Context, id string) (*domain.ConsentRecord, error) {
	return m.FindByIDFn(ctx, id)
}

// FindByUserID delegates to FindByUserIDFn.
func (m *MockGDPRConsentRepository) FindByUserID(ctx context.Context, userID string) ([]domain.ConsentRecord, error) {
	return m.FindByUserIDFn(ctx, userID)
}

// FindByUserIDAndType delegates to FindByUserIDAndTypeFn.
func (m *MockGDPRConsentRepository) FindByUserIDAndType(ctx context.Context, userID, consentType string) (*domain.ConsentRecord, error) {
	return m.FindByUserIDAndTypeFn(ctx, userID, consentType)
}

// Revoke delegates to RevokeFn.
func (m *MockGDPRConsentRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	return m.RevokeFn(ctx, id, revokedAt)
}

// DeleteByUserID delegates to DeleteByUserIDFn.
func (m *MockGDPRConsentRepository) DeleteByUserID(ctx context.Context, userID string) error {
	return m.DeleteByUserIDFn(ctx, userID)
}
