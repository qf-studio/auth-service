package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/webhook"
)

const (
	// webhookSecretBytes is the number of random bytes for webhook secret generation (256-bit).
	webhookSecretBytes = 32
)

// WebhookService implements api.AdminWebhookService.
type WebhookService struct {
	webhookRepo  storage.WebhookRepository
	deliveryRepo storage.WebhookDeliveryRepository
	dispatcher   *webhook.Dispatcher
	logger       *zap.Logger
	audit        audit.EventLogger
}

// NewWebhookService creates a new admin webhook service.
func NewWebhookService(
	webhookRepo storage.WebhookRepository,
	deliveryRepo storage.WebhookDeliveryRepository,
	dispatcher *webhook.Dispatcher,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *WebhookService {
	return &WebhookService{
		webhookRepo:  webhookRepo,
		deliveryRepo: deliveryRepo,
		dispatcher:   dispatcher,
		logger:       logger,
		audit:        auditor,
	}
}

// ListWebhooks returns a paginated list of webhooks.
func (s *WebhookService) ListWebhooks(ctx context.Context, page, perPage int, activeOnly bool) (*api.AdminWebhookList, error) {
	offset := (page - 1) * perPage

	webhooks, total, err := s.webhookRepo.List(ctx, perPage, offset, activeOnly)
	if err != nil {
		s.logger.Error("list webhooks failed", zap.Error(err))
		return nil, fmt.Errorf("list webhooks: %w", api.ErrInternalError)
	}

	result := &api.AdminWebhookList{
		Webhooks: make([]api.AdminWebhook, 0, len(webhooks)),
		Total:    total,
		Page:     page,
		PerPage:  perPage,
	}

	for _, wh := range webhooks {
		result.Webhooks = append(result.Webhooks, domainWebhookToAdmin(wh))
	}

	return result, nil
}

// GetWebhook retrieves a single webhook by ID.
func (s *WebhookService) GetWebhook(ctx context.Context, webhookID string) (*api.AdminWebhook, error) {
	id, err := uuid.Parse(webhookID)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	wh, err := s.webhookRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("get webhook failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("get webhook: %w", api.ErrInternalError)
	}

	admin := domainWebhookToAdmin(wh)
	return &admin, nil
}

// CreateWebhook creates a new webhook subscription with a generated signing secret.
func (s *WebhookService) CreateWebhook(ctx context.Context, req *api.CreateWebhookRequest) (*api.AdminWebhookWithSecret, error) {
	secret, err := generateWebhookSecret()
	if err != nil {
		s.logger.Error("generate webhook secret failed", zap.Error(err))
		return nil, fmt.Errorf("create webhook: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()
	eventTypes := req.EventTypes
	if eventTypes == nil {
		eventTypes = []string{}
	}

	wh := &domain.Webhook{
		ID:           uuid.New(),
		URL:          req.URL,
		SecretHash:   secret, // stored as the raw secret for HMAC signing
		EventTypes:   eventTypes,
		Active:       true,
		FailureCount: 0,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	created, err := s.webhookRepo.Create(ctx, wh)
	if err != nil {
		s.logger.Error("create webhook failed", zap.Error(err))
		return nil, fmt.Errorf("create webhook: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminWebhookCreate,
		TargetID: created.ID.String(),
		Metadata: map[string]string{"url": created.URL},
	})

	return &api.AdminWebhookWithSecret{
		AdminWebhook: domainWebhookToAdmin(created),
		Secret:       secret,
	}, nil
}

// UpdateWebhook modifies webhook fields (url, event_types, active).
func (s *WebhookService) UpdateWebhook(ctx context.Context, webhookID string, req *api.UpdateWebhookRequest) (*api.AdminWebhook, error) {
	id, err := uuid.Parse(webhookID)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	existing, err := s.webhookRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("find webhook for update failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("update webhook: %w", api.ErrInternalError)
	}

	if req.URL != nil {
		existing.URL = *req.URL
	}
	if req.EventTypes != nil {
		existing.EventTypes = req.EventTypes
	}
	if req.Active != nil {
		existing.Active = *req.Active
	}

	updated, err := s.webhookRepo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("update webhook failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("update webhook: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminWebhookUpdate,
		TargetID: webhookID,
	})

	admin := domainWebhookToAdmin(updated)
	return &admin, nil
}

// DeleteWebhook removes a webhook by ID.
func (s *WebhookService) DeleteWebhook(ctx context.Context, webhookID string) error {
	id, err := uuid.Parse(webhookID)
	if err != nil {
		return fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	err = s.webhookRepo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("delete webhook failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return fmt.Errorf("delete webhook: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminWebhookDelete,
		TargetID: webhookID,
	})
	return nil
}

// ListDeliveries returns a paginated list of delivery log entries for a webhook.
func (s *WebhookService) ListDeliveries(ctx context.Context, webhookID string, page, perPage int) (*api.AdminWebhookDeliveryList, error) {
	id, err := uuid.Parse(webhookID)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	// Verify webhook exists.
	if _, err := s.webhookRepo.FindByID(ctx, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("find webhook for deliveries failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("list deliveries: %w", api.ErrInternalError)
	}

	offset := (page - 1) * perPage
	deliveries, total, err := s.deliveryRepo.List(ctx, id, perPage, offset)
	if err != nil {
		s.logger.Error("list deliveries failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("list deliveries: %w", api.ErrInternalError)
	}

	result := &api.AdminWebhookDeliveryList{
		Deliveries: make([]api.AdminWebhookDelivery, 0, len(deliveries)),
		Total:      total,
		Page:       page,
		PerPage:    perPage,
	}

	for _, d := range deliveries {
		result.Deliveries = append(result.Deliveries, domainDeliveryToAdmin(d))
	}

	return result, nil
}

// RetryDelivery manually retries a failed webhook delivery.
func (s *WebhookService) RetryDelivery(ctx context.Context, webhookID, deliveryID string) (*api.AdminWebhookDelivery, error) {
	whID, err := uuid.Parse(webhookID)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	dID, err := uuid.Parse(deliveryID)
	if err != nil {
		return nil, fmt.Errorf("invalid delivery ID: %w", api.ErrNotFound)
	}

	wh, err := s.webhookRepo.FindByID(ctx, whID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("find webhook for retry failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("retry delivery: %w", api.ErrInternalError)
	}

	existing, err := s.deliveryRepo.FindByID(ctx, dID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("delivery %s: %w", deliveryID, api.ErrNotFound)
		}
		s.logger.Error("find delivery for retry failed", zap.String("delivery_id", deliveryID), zap.Error(err))
		return nil, fmt.Errorf("retry delivery: %w", api.ErrInternalError)
	}

	if existing.WebhookID != whID {
		return nil, fmt.Errorf("delivery %s does not belong to webhook %s: %w", deliveryID, webhookID, api.ErrNotFound)
	}

	// Re-deliver using the existing payload.
	var payload webhook.Payload
	if err := json.Unmarshal([]byte(existing.Payload), &payload); err != nil {
		// If we can't parse the stored payload, construct a minimal one.
		payload = webhook.Payload{
			ID:        uuid.New().String(),
			EventType: existing.EventType,
			Timestamp: time.Now().UTC(),
		}
	}

	delivery, err := s.dispatcher.DeliverSingle(ctx, wh, payload)
	if err != nil {
		// Delivery failed but we still return the delivery record.
		if delivery != nil {
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventAdminWebhookRetry,
				TargetID: deliveryID,
				Metadata: map[string]string{"webhook_id": webhookID, "status": delivery.Status},
			})
			admin := domainDeliveryToAdmin(delivery)
			return &admin, nil
		}
		s.logger.Error("retry delivery failed", zap.String("delivery_id", deliveryID), zap.Error(err))
		return nil, fmt.Errorf("retry delivery: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminWebhookRetry,
		TargetID: deliveryID,
		Metadata: map[string]string{"webhook_id": webhookID, "status": delivery.Status},
	})

	admin := domainDeliveryToAdmin(delivery)
	return &admin, nil
}

// TestWebhook sends a test event to a webhook and returns the delivery result.
func (s *WebhookService) TestWebhook(ctx context.Context, webhookID string, req *api.TestWebhookRequest) (*api.TestWebhookResponse, error) {
	id, err := uuid.Parse(webhookID)
	if err != nil {
		return nil, fmt.Errorf("invalid webhook ID: %w", api.ErrNotFound)
	}

	wh, err := s.webhookRepo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", webhookID, api.ErrNotFound)
		}
		s.logger.Error("find webhook for test failed", zap.String("webhook_id", webhookID), zap.Error(err))
		return nil, fmt.Errorf("test webhook: %w", api.ErrInternalError)
	}

	payload := webhook.Payload{
		ID:        uuid.New().String(),
		EventType: req.EventType,
		Timestamp: time.Now().UTC(),
		Data:      map[string]string{"test": "true"},
	}

	delivery, deliverErr := s.dispatcher.DeliverSingle(ctx, wh, payload)
	if delivery == nil {
		s.logger.Error("test webhook delivery returned nil", zap.String("webhook_id", webhookID), zap.Error(deliverErr))
		return nil, fmt.Errorf("test webhook: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminWebhookTest,
		TargetID: webhookID,
		Metadata: map[string]string{"event_type": req.EventType, "delivery_status": delivery.Status},
	})

	return &api.TestWebhookResponse{
		DeliveryID:   delivery.ID.String(),
		Status:       delivery.Status,
		ResponseCode: delivery.ResponseCode,
	}, nil
}

// generateWebhookSecret generates a cryptographically random secret for HMAC signing.
func generateWebhookSecret() (string, error) {
	b := make([]byte, webhookSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return "whsec_" + hex.EncodeToString(b), nil
}

func domainWebhookToAdmin(wh *domain.Webhook) api.AdminWebhook {
	return api.AdminWebhook{
		ID:           wh.ID.String(),
		URL:          wh.URL,
		EventTypes:   wh.EventTypes,
		Active:       wh.Active,
		FailureCount: wh.FailureCount,
		CreatedAt:    wh.CreatedAt,
		UpdatedAt:    wh.UpdatedAt,
	}
}

func domainDeliveryToAdmin(d *domain.WebhookDelivery) api.AdminWebhookDelivery {
	return api.AdminWebhookDelivery{
		ID:           d.ID.String(),
		WebhookID:    d.WebhookID.String(),
		EventType:    d.EventType,
		Payload:      d.Payload,
		Status:       d.Status,
		ResponseCode: d.ResponseCode,
		ResponseBody: d.ResponseBody,
		Attempt:      d.Attempt,
		NextRetryAt:  d.NextRetryAt,
		DeliveredAt:  d.DeliveredAt,
		CreatedAt:    d.CreatedAt,
	}
}
