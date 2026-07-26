package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockConsentGrantRepository is a configurable mock for storage.ConsentGrantRepository.
type MockConsentGrantRepository struct {
	FindActiveFn func(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error)
	CreateFn     func(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error)
}

// FindActive delegates to FindActiveFn.
func (m *MockConsentGrantRepository) FindActive(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error) {
	return m.FindActiveFn(ctx, tenantID, userID, clientID)
}

// Create delegates to CreateFn.
func (m *MockConsentGrantRepository) Create(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error) {
	return m.CreateFn(ctx, grant)
}
