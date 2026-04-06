package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockWebhookRepository is a test double for storage.WebhookRepository.
type MockWebhookRepository struct {
	CreateWebhookFn          func(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error)
	GetWebhookFn             func(ctx context.Context, id string) (*domain.Webhook, error)
	ListWebhooksFn           func(ctx context.Context, activeOnly bool) ([]domain.Webhook, error)
	UpdateWebhookFn          func(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error)
	DeleteWebhookFn          func(ctx context.Context, id string) error
	CreateDeliveryFn         func(ctx context.Context, delivery *domain.WebhookDelivery) (*domain.WebhookDelivery, error)
	GetDeliveryFn            func(ctx context.Context, id string) (*domain.WebhookDelivery, error)
	ListDeliveriesByWebhookFn func(ctx context.Context, webhookID string) ([]domain.WebhookDelivery, error)
	ListDeliveriesByStatusFn  func(ctx context.Context, status string) ([]domain.WebhookDelivery, error)
	UpdateDeliveryFn         func(ctx context.Context, delivery *domain.WebhookDelivery) error
	IncrementFailureCountFn  func(ctx context.Context, webhookID string) (int, error)
	ResetFailureCountFn      func(ctx context.Context, webhookID string) error
}

func (m *MockWebhookRepository) CreateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error) {
	return m.CreateWebhookFn(ctx, webhook)
}

func (m *MockWebhookRepository) GetWebhook(ctx context.Context, id string) (*domain.Webhook, error) {
	return m.GetWebhookFn(ctx, id)
}

func (m *MockWebhookRepository) ListWebhooks(ctx context.Context, activeOnly bool) ([]domain.Webhook, error) {
	return m.ListWebhooksFn(ctx, activeOnly)
}

func (m *MockWebhookRepository) UpdateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error) {
	return m.UpdateWebhookFn(ctx, webhook)
}

func (m *MockWebhookRepository) DeleteWebhook(ctx context.Context, id string) error {
	return m.DeleteWebhookFn(ctx, id)
}

func (m *MockWebhookRepository) CreateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	return m.CreateDeliveryFn(ctx, delivery)
}

func (m *MockWebhookRepository) GetDelivery(ctx context.Context, id string) (*domain.WebhookDelivery, error) {
	return m.GetDeliveryFn(ctx, id)
}

func (m *MockWebhookRepository) ListDeliveriesByWebhook(ctx context.Context, webhookID string) ([]domain.WebhookDelivery, error) {
	return m.ListDeliveriesByWebhookFn(ctx, webhookID)
}

func (m *MockWebhookRepository) ListDeliveriesByStatus(ctx context.Context, status string) ([]domain.WebhookDelivery, error) {
	return m.ListDeliveriesByStatusFn(ctx, status)
}

func (m *MockWebhookRepository) UpdateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error {
	return m.UpdateDeliveryFn(ctx, delivery)
}

func (m *MockWebhookRepository) IncrementFailureCount(ctx context.Context, webhookID string) (int, error) {
	return m.IncrementFailureCountFn(ctx, webhookID)
}

func (m *MockWebhookRepository) ResetFailureCount(ctx context.Context, webhookID string) error {
	return m.ResetFailureCountFn(ctx, webhookID)
}
