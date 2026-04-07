package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// --- In-memory test repositories ---

type memWebhookRepo struct {
	webhooks []*domain.Webhook
}

func (r *memWebhookRepo) List(_ context.Context, _ uuid.UUID, limit, offset int, _ bool) ([]*domain.Webhook, int, error) {
	total := len(r.webhooks)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return r.webhooks[offset:end], total, nil
}

func (r *memWebhookRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.Webhook, error) {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			return wh, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memWebhookRepo) FindActiveByEventType(_ context.Context, _ uuid.UUID, eventType string) ([]*domain.Webhook, error) {
	var result []*domain.Webhook
	for _, wh := range r.webhooks {
		if !wh.Active {
			continue
		}
		for _, et := range wh.EventTypes {
			if et == eventType {
				result = append(result, wh)
				break
			}
		}
	}
	return result, nil
}

func (r *memWebhookRepo) Create(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	r.webhooks = append(r.webhooks, wh)
	return wh, nil
}

func (r *memWebhookRepo) Update(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	for i, existing := range r.webhooks {
		if existing.ID == wh.ID {
			r.webhooks[i] = wh
			return wh, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memWebhookRepo) Delete(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for i, wh := range r.webhooks {
		if wh.ID == id {
			r.webhooks = append(r.webhooks[:i], r.webhooks[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("not found")
}

func (r *memWebhookRepo) IncrementFailureCount(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.FailureCount++
			return nil
		}
	}
	return nil
}

func (r *memWebhookRepo) ResetFailureCount(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.FailureCount = 0
			return nil
		}
	}
	return nil
}

func (r *memWebhookRepo) Disable(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	for _, wh := range r.webhooks {
		if wh.ID == id {
			wh.Active = false
			return nil
		}
	}
	return nil
}

type memDeliveryRepo struct {
	deliveries []*domain.WebhookDelivery
}

func (r *memDeliveryRepo) List(_ context.Context, _ uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error) {
	var filtered []*domain.WebhookDelivery
	for _, d := range r.deliveries {
		if d.WebhookID == webhookID {
			filtered = append(filtered, d)
		}
	}
	total := len(filtered)
	if offset >= total {
		return nil, total, nil
	}
	end := offset + limit
	if end > total {
		end = total
	}
	return filtered[offset:end], total, nil
}

func (r *memDeliveryRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error) {
	for _, d := range r.deliveries {
		if d.ID == id {
			return d, nil
		}
	}
	return nil, fmt.Errorf("not found")
}

func (r *memDeliveryRepo) Create(_ context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	r.deliveries = append(r.deliveries, d)
	return d, nil
}

func (r *memDeliveryRepo) UpdateStatus(_ context.Context, _ uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error {
	for _, d := range r.deliveries {
		if d.ID == id {
			d.Status = status
			d.ResponseCode = responseCode
			d.ResponseBody = responseBody
			d.DeliveredAt = deliveredAt
			return nil
		}
	}
	return nil
}

func (r *memDeliveryRepo) FindPendingRetries(_ context.Context, _ uuid.UUID, _ time.Time, _ int) ([]*domain.WebhookDelivery, error) {
	return nil, nil
}

// --- Tests ---

func TestDeliverSingle_Success(t *testing.T) {
	var called atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called.Add(1)

		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.NotEmpty(t, r.Header.Get(signatureHeader))
		assert.Equal(t, "test_event", r.Header.Get(eventTypeHeader))
		assert.NotEmpty(t, r.Header.Get(deliveryIDHeader))

		var p Payload
		require.NoError(t, json.NewDecoder(r.Body).Decode(&p))
		assert.Equal(t, "test_event", p.EventType)

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer ts.Close()

	whRepo := &memWebhookRepo{}
	delRepo := &memDeliveryRepo{}
	logger := zap.NewNop()
	d := NewDispatcher(whRepo, delRepo, logger)
	defer func() { _ = d.Close() }()

	wh := &domain.Webhook{
		ID:         uuid.New(),
		URL:        ts.URL,
		SecretHash: "test-secret",
		EventTypes: []string{"test_event"},
		Active:     true,
	}

	payload := Payload{
		ID:        uuid.New().String(),
		EventType: "test_event",
		Timestamp: time.Now().UTC(),
		Data:      map[string]string{"key": "value"},
	}

	delivery, err := d.DeliverSingle(context.Background(), wh, payload)
	require.NoError(t, err)

	assert.Equal(t, int32(1), called.Load())
	assert.Equal(t, domain.WebhookDeliveryStatusDelivered, delivery.Status)
	assert.NotNil(t, delivery.ResponseCode)
	assert.Equal(t, 200, *delivery.ResponseCode)
	assert.NotNil(t, delivery.DeliveredAt)
}

func TestDeliverSingle_ServerError(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"boom"}`))
	}))
	defer ts.Close()

	whRepo := &memWebhookRepo{}
	delRepo := &memDeliveryRepo{}
	logger := zap.NewNop()
	d := NewDispatcher(whRepo, delRepo, logger)
	defer func() { _ = d.Close() }()

	wh := &domain.Webhook{
		ID:         uuid.New(),
		URL:        ts.URL,
		SecretHash: "test-secret",
		EventTypes: []string{"test_event"},
		Active:     true,
	}

	payload := Payload{
		ID:        uuid.New().String(),
		EventType: "test_event",
		Timestamp: time.Now().UTC(),
	}

	delivery, err := d.DeliverSingle(context.Background(), wh, payload)
	require.Error(t, err)
	require.NotNil(t, delivery)
	assert.Equal(t, 500, *delivery.ResponseCode)
}

func TestDispatcher_NameAndClose(t *testing.T) {
	d := NewDispatcher(&memWebhookRepo{}, &memDeliveryRepo{}, zap.NewNop())
	assert.Equal(t, "webhook-dispatcher", d.Name())
	require.NoError(t, d.Close())
}

func TestHMACSignature(t *testing.T) {
	var receivedSig string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get(signatureHeader)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer ts.Close()

	whRepo := &memWebhookRepo{}
	delRepo := &memDeliveryRepo{}
	d := NewDispatcher(whRepo, delRepo, zap.NewNop())
	defer func() { _ = d.Close() }()

	wh := &domain.Webhook{
		ID:         uuid.New(),
		URL:        ts.URL,
		SecretHash: "my-signing-key",
		EventTypes: []string{"test"},
		Active:     true,
	}

	payload := Payload{
		ID:        "test-id",
		EventType: "test",
		Timestamp: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	}

	_, err := d.DeliverSingle(context.Background(), wh, payload)
	require.NoError(t, err)
	assert.True(t, len(receivedSig) > 7, "signature should be present")
	assert.Equal(t, "sha256=", receivedSig[:7])
}
