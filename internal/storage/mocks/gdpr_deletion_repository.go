package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockGDPRDeletionRepository is a configurable mock for storage.GDPRDeletionRepository.
type MockGDPRDeletionRepository struct {
	CreateFn              func(ctx context.Context, req *domain.DeletionRequest) (*domain.DeletionRequest, error)
	FindByIDFn            func(ctx context.Context, id string) (*domain.DeletionRequest, error)
	FindByUserIDFn        func(ctx context.Context, userID string) (*domain.DeletionRequest, error)
	FindPendingByUserIDFn func(ctx context.Context, userID string) (*domain.DeletionRequest, error)
	FindDueForExecutionFn func(ctx context.Context, now time.Time) ([]domain.DeletionRequest, error)
	UpdateStatusFn        func(ctx context.Context, id, status string, now time.Time) error
	CancelFn              func(ctx context.Context, id, cancelledBy string, cancelledAt time.Time) error
}

// Create delegates to CreateFn.
func (m *MockGDPRDeletionRepository) Create(ctx context.Context, req *domain.DeletionRequest) (*domain.DeletionRequest, error) {
	return m.CreateFn(ctx, req)
}

// FindByID delegates to FindByIDFn.
func (m *MockGDPRDeletionRepository) FindByID(ctx context.Context, id string) (*domain.DeletionRequest, error) {
	return m.FindByIDFn(ctx, id)
}

// FindByUserID delegates to FindByUserIDFn.
func (m *MockGDPRDeletionRepository) FindByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error) {
	return m.FindByUserIDFn(ctx, userID)
}

// FindPendingByUserID delegates to FindPendingByUserIDFn.
func (m *MockGDPRDeletionRepository) FindPendingByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error) {
	return m.FindPendingByUserIDFn(ctx, userID)
}

// FindDueForExecution delegates to FindDueForExecutionFn.
func (m *MockGDPRDeletionRepository) FindDueForExecution(ctx context.Context, now time.Time) ([]domain.DeletionRequest, error) {
	return m.FindDueForExecutionFn(ctx, now)
}

// UpdateStatus delegates to UpdateStatusFn.
func (m *MockGDPRDeletionRepository) UpdateStatus(ctx context.Context, id, status string, now time.Time) error {
	return m.UpdateStatusFn(ctx, id, status, now)
}

// Cancel delegates to CancelFn.
func (m *MockGDPRDeletionRepository) Cancel(ctx context.Context, id, cancelledBy string, cancelledAt time.Time) error {
	return m.CancelFn(ctx, id, cancelledBy, cancelledAt)
}
