package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebhookRepository defines persistence operations for webhooks and deliveries.
type WebhookRepository interface {
	// Webhook CRUD
	CreateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error)
	GetWebhook(ctx context.Context, id string) (*domain.Webhook, error)
	ListWebhooks(ctx context.Context, activeOnly bool) ([]domain.Webhook, error)
	UpdateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error)
	DeleteWebhook(ctx context.Context, id string) error

	// Delivery operations
	CreateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) (*domain.WebhookDelivery, error)
	GetDelivery(ctx context.Context, id string) (*domain.WebhookDelivery, error)
	ListDeliveriesByWebhook(ctx context.Context, webhookID string) ([]domain.WebhookDelivery, error)
	ListDeliveriesByStatus(ctx context.Context, status string) ([]domain.WebhookDelivery, error)
	UpdateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error

	// Failure tracking
	IncrementFailureCount(ctx context.Context, webhookID string) (int, error)
	ResetFailureCount(ctx context.Context, webhookID string) error
}
