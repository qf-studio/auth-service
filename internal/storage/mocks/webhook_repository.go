package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockWebhookRepository is a configurable mock for storage.WebhookRepository.
type MockWebhookRepository struct {
	ListFn                  func(ctx context.Context, tenantID uuid.UUID, limit, offset int, activeOnly bool) ([]*domain.Webhook, int, error)
	FindByIDFn              func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Webhook, error)
	FindActiveByEventTypeFn func(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*domain.Webhook, error)
	CreateFn                func(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)
	UpdateFn                func(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)
	DeleteFn                func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	IncrementFailureCountFn func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	ResetFailureCountFn     func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	DisableFn               func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// List delegates to ListFn.
func (m *MockWebhookRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, activeOnly bool) ([]*domain.Webhook, int, error) {
	return m.ListFn(ctx, tenantID, limit, offset, activeOnly)
}

// FindByID delegates to FindByIDFn.
func (m *MockWebhookRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Webhook, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// FindActiveByEventType delegates to FindActiveByEventTypeFn.
func (m *MockWebhookRepository) FindActiveByEventType(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*domain.Webhook, error) {
	return m.FindActiveByEventTypeFn(ctx, tenantID, eventType)
}

// Create delegates to CreateFn.
func (m *MockWebhookRepository) Create(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	return m.CreateFn(ctx, wh)
}

// Update delegates to UpdateFn.
func (m *MockWebhookRepository) Update(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	return m.UpdateFn(ctx, wh)
}

// Delete delegates to DeleteFn.
func (m *MockWebhookRepository) Delete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.DeleteFn(ctx, tenantID, id)
}

// IncrementFailureCount delegates to IncrementFailureCountFn.
func (m *MockWebhookRepository) IncrementFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.IncrementFailureCountFn(ctx, tenantID, id)
}

// ResetFailureCount delegates to ResetFailureCountFn.
func (m *MockWebhookRepository) ResetFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.ResetFailureCountFn(ctx, tenantID, id)
}

// Disable delegates to DisableFn.
func (m *MockWebhookRepository) Disable(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	return m.DisableFn(ctx, tenantID, id)
}

// MockWebhookDeliveryRepository is a configurable mock for storage.WebhookDeliveryRepository.
type MockWebhookDeliveryRepository struct {
	ListFn              func(ctx context.Context, tenantID uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error)
	FindByIDFn          func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error)
	CreateFn            func(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error)
	UpdateStatusFn      func(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error
	FindPendingRetriesFn func(ctx context.Context, tenantID uuid.UUID, before time.Time, limit int) ([]*domain.WebhookDelivery, error)
}

// List delegates to ListFn.
func (m *MockWebhookDeliveryRepository) List(ctx context.Context, tenantID uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error) {
	return m.ListFn(ctx, tenantID, webhookID, limit, offset)
}

// FindByID delegates to FindByIDFn.
func (m *MockWebhookDeliveryRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error) {
	return m.FindByIDFn(ctx, tenantID, id)
}

// Create delegates to CreateFn.
func (m *MockWebhookDeliveryRepository) Create(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	return m.CreateFn(ctx, d)
}

// UpdateStatus delegates to UpdateStatusFn.
func (m *MockWebhookDeliveryRepository) UpdateStatus(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error {
	return m.UpdateStatusFn(ctx, tenantID, id, status, responseCode, responseBody, deliveredAt)
}

// FindPendingRetries delegates to FindPendingRetriesFn.
func (m *MockWebhookDeliveryRepository) FindPendingRetries(ctx context.Context, tenantID uuid.UUID, before time.Time, limit int) ([]*domain.WebhookDelivery, error) {
	return m.FindPendingRetriesFn(ctx, tenantID, before, limit)
}
