// Package webhook provides an async webhook dispatcher that delivers HTTP POST
// notifications to registered webhook endpoints when audit events fire.
package webhook

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	deliveryTimeout   = 5 * time.Second
	maxRetries        = 3
	dispatchBufSize   = 256
	signatureHeader   = "X-Signature-256"
	eventTypeHeader   = "X-Webhook-Event"
	deliveryIDHeader  = "X-Webhook-Delivery"
)

// retryDelays defines backoff intervals for retry attempts (1s, 5s, 25s).
var retryDelays = []time.Duration{1 * time.Second, 5 * time.Second, 25 * time.Second}

// Payload is the structure sent as the webhook HTTP body.
type Payload struct {
	ID        string            `json:"id"`
	EventType string            `json:"event_type"`
	Timestamp time.Time         `json:"timestamp"`
	Data      map[string]string `json:"data,omitempty"`
}

// Dispatcher delivers webhook events asynchronously to subscribed endpoints.
type Dispatcher struct {
	webhookRepo  storage.WebhookRepository
	deliveryRepo storage.WebhookDeliveryRepository
	logger       *zap.Logger
	httpClient   *http.Client
	ch           chan dispatchJob
	done         chan struct{}
}

type dispatchJob struct {
	webhook *domain.Webhook
	payload Payload
}

// NewDispatcher creates a webhook Dispatcher with background workers.
func NewDispatcher(
	webhookRepo storage.WebhookRepository,
	deliveryRepo storage.WebhookDeliveryRepository,
	logger *zap.Logger,
) *Dispatcher {
	d := &Dispatcher{
		webhookRepo:  webhookRepo,
		deliveryRepo: deliveryRepo,
		logger:       logger,
		httpClient: &http.Client{
			Timeout: deliveryTimeout,
		},
		ch:   make(chan dispatchJob, dispatchBufSize),
		done: make(chan struct{}),
	}
	go d.worker()
	return d
}

// Dispatch enqueues a webhook delivery for all webhooks subscribed to the event type.
func (d *Dispatcher) Dispatch(ctx context.Context, eventType string, data map[string]string) {
	tenantID := domain.TenantIDFromContext(ctx)
	webhooks, err := d.webhookRepo.FindActiveByEventType(ctx, tenantID, eventType)
	if err != nil {
		d.logger.Error("find webhooks for dispatch failed", zap.String("event_type", eventType), zap.Error(err))
		return
	}

	payload := Payload{
		ID:        uuid.New().String(),
		EventType: eventType,
		Timestamp: time.Now().UTC(),
		Data:      data,
	}

	for _, wh := range webhooks {
		select {
		case d.ch <- dispatchJob{webhook: wh, payload: payload}:
		default:
			d.logger.Warn("webhook dispatch buffer full, dropping",
				zap.String("webhook_id", wh.ID.String()),
				zap.String("event_type", eventType),
			)
		}
	}
}

// DeliverSingle performs a synchronous delivery to a specific webhook. Used for
// test and manual retry endpoints.
func (d *Dispatcher) DeliverSingle(ctx context.Context, wh *domain.Webhook, payload Payload) (*domain.WebhookDelivery, error) {
	return d.deliver(ctx, wh, payload)
}

// Name returns the closer label for shutdown logging.
func (d *Dispatcher) Name() string { return "webhook-dispatcher" }

// Close signals the worker to drain and waits for completion.
func (d *Dispatcher) Close() error {
	close(d.ch)
	<-d.done
	return nil
}

func (d *Dispatcher) worker() {
	defer close(d.done)
	for job := range d.ch {
		ctx := context.Background()
		if _, err := d.deliver(ctx, job.webhook, job.payload); err != nil {
			d.logger.Error("webhook delivery failed",
				zap.String("webhook_id", job.webhook.ID.String()),
				zap.Error(err),
			)
		}
	}
}

func (d *Dispatcher) deliver(ctx context.Context, wh *domain.Webhook, payload Payload) (*domain.WebhookDelivery, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal webhook payload: %w", err)
	}

	now := time.Now().UTC()
	delivery := &domain.WebhookDelivery{
		ID:        uuid.New(),
		TenantID:  wh.TenantID,
		WebhookID: wh.ID,
		EventType: payload.EventType,
		Payload:   string(body),
		Status:    domain.WebhookDeliveryStatusPending,
		Attempt:   1,
		CreatedAt: now,
	}

	delivery, err = d.deliveryRepo.Create(ctx, delivery)
	if err != nil {
		return nil, fmt.Errorf("create delivery record: %w", err)
	}

	responseCode, responseBody, deliverErr := d.doHTTPPost(ctx, wh, body, payload)

	if deliverErr == nil {
		deliveredAt := time.Now().UTC()
		delivery.Status = domain.WebhookDeliveryStatusDelivered
		delivery.ResponseCode = responseCode
		delivery.ResponseBody = responseBody
		delivery.DeliveredAt = &deliveredAt
		_ = d.deliveryRepo.UpdateStatus(ctx, wh.TenantID, delivery.ID, delivery.Status, responseCode, responseBody, &deliveredAt)
		_ = d.webhookRepo.ResetFailureCount(ctx, wh.TenantID, wh.ID)
		return delivery, nil
	}

	// Delivery failed — schedule retry if within limits.
	delivery.ResponseCode = responseCode
	delivery.ResponseBody = responseBody
	_ = d.webhookRepo.IncrementFailureCount(ctx, wh.TenantID, wh.ID)

	if delivery.Attempt < maxRetries {
		retryAt := time.Now().UTC().Add(retryDelays[delivery.Attempt-1])
		delivery.NextRetryAt = &retryAt
		delivery.Status = domain.WebhookDeliveryStatusPending
	} else {
		delivery.Status = domain.WebhookDeliveryStatusFailed
	}

	_ = d.deliveryRepo.UpdateStatus(ctx, wh.TenantID, delivery.ID, delivery.Status, responseCode, responseBody, nil)

	// Auto-disable webhook after too many consecutive failures.
	if wh.FailureCount+1 >= domain.MaxWebhookFailures {
		_ = d.webhookRepo.Disable(ctx, wh.TenantID, wh.ID)
		d.logger.Warn("webhook auto-disabled due to excessive failures",
			zap.String("webhook_id", wh.ID.String()),
			zap.Int("failure_count", wh.FailureCount+1),
		)
	}

	return delivery, deliverErr
}

func (d *Dispatcher) doHTTPPost(ctx context.Context, wh *domain.Webhook, body []byte, payload Payload) (*int, *string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(body))
	if err != nil {
		return nil, nil, fmt.Errorf("create webhook request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(eventTypeHeader, payload.EventType)
	req.Header.Set(deliveryIDHeader, payload.ID)

	// HMAC-SHA256 signature using the webhook's secret hash as the key.
	if wh.SecretHash != "" {
		mac := hmac.New(sha256.New, []byte(wh.SecretHash))
		mac.Write(body)
		sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
		req.Header.Set(signatureHeader, sig)
	}

	resp, err := d.httpClient.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("webhook HTTP request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	code := resp.StatusCode
	respStr := string(respBody)

	if code >= 200 && code < 300 {
		return &code, &respStr, nil
	}

	return &code, &respStr, fmt.Errorf("webhook returned status %d", code)
}
