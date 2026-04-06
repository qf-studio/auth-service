package webhook

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Service handles webhook CRUD operations.
type Service struct {
	repo   storage.WebhookRepository
	logger *zap.Logger
}

// NewService creates a webhook management service.
func NewService(logger *zap.Logger, repo storage.WebhookRepository) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
	}
}

// CreateInput holds fields for creating a new webhook.
type CreateInput struct {
	URL        string
	EventTypes []string
}

// Create registers a new webhook. A signing secret is auto-generated.
func (s *Service) Create(ctx context.Context, input CreateInput) (*domain.Webhook, error) {
	secret, err := generateSecret(32)
	if err != nil {
		return nil, fmt.Errorf("generate webhook secret: %w", err)
	}

	now := time.Now().UTC()
	wh := &domain.Webhook{
		ID:           uuid.New().String(),
		URL:          input.URL,
		Secret:       secret,
		EventTypes:   input.EventTypes,
		Active:       true,
		FailureCount: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.repo.CreateWebhook(ctx, wh)
	if err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}

	s.logger.Info("webhook created",
		zap.String("webhook_id", created.ID),
		zap.String("url", created.URL),
	)
	return created, nil
}

// Get retrieves a webhook by ID.
func (s *Service) Get(ctx context.Context, id string) (*domain.Webhook, error) {
	wh, err := s.repo.GetWebhook(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	return wh, nil
}

// List returns webhooks, optionally filtered to active only.
func (s *Service) List(ctx context.Context, activeOnly bool) ([]*domain.Webhook, error) {
	webhooks, err := s.repo.ListWebhooks(ctx, activeOnly)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	return webhooks, nil
}

// UpdateInput holds mutable fields for updating a webhook.
type UpdateInput struct {
	URL        *string
	EventTypes []string
	Active     *bool
}

// Update modifies a webhook's mutable fields.
func (s *Service) Update(ctx context.Context, id string, input UpdateInput) (*domain.Webhook, error) {
	existing, err := s.repo.GetWebhook(ctx, id)
	if err != nil {
		return nil, fmt.Errorf("get webhook for update: %w", err)
	}
	if existing == nil {
		return nil, fmt.Errorf("get webhook for update: %w", storage.ErrNotFound)
	}

	if input.URL != nil {
		existing.URL = *input.URL
	}
	if input.EventTypes != nil {
		existing.EventTypes = input.EventTypes
	}
	if input.Active != nil {
		existing.Active = *input.Active
	}
	existing.UpdatedAt = time.Now().UTC()

	updated, err := s.repo.UpdateWebhook(ctx, existing)
	if err != nil {
		return nil, fmt.Errorf("update webhook: %w", err)
	}

	s.logger.Info("webhook updated",
		zap.String("webhook_id", updated.ID),
	)
	return updated, nil
}

// Delete removes a webhook by ID.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.repo.DeleteWebhook(ctx, id); err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}

	s.logger.Info("webhook deleted", zap.String("webhook_id", id))
	return nil
}

// generateSecret creates a cryptographically random hex-encoded secret.
func generateSecret(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
