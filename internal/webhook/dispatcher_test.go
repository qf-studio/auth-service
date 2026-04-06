package webhook

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"

	"github.com/qf-studio/auth-service/internal/domain"
)

// mockWebhookRepo implements storage.WebhookRepository for unit tests.
type mockWebhookRepo struct {
	mu               sync.Mutex
	webhooks         map[string]*domain.Webhook
	deliveries       []*domain.WebhookDelivery
	failureIncrCount int
	disableCalled    bool
	resetCalled      bool
}

func newMockRepo() *mockWebhookRepo {
	return &mockWebhookRepo{
		webhooks: make(map[string]*domain.Webhook),
	}
}

func (m *mockWebhookRepo) CreateWebhook(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhooks[wh.ID] = wh
	return wh, nil
}

func (m *mockWebhookRepo) GetWebhook(_ context.Context, id string) (*domain.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if wh, ok := m.webhooks[id]; ok {
		return wh, nil
	}
	return nil, nil
}

func (m *mockWebhookRepo) ListWebhooks(_ context.Context, activeOnly bool) ([]*domain.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*domain.Webhook
	for _, wh := range m.webhooks {
		if activeOnly && !wh.Active {
			continue
		}
		result = append(result, wh)
	}
	return result, nil
}

func (m *mockWebhookRepo) UpdateWebhook(_ context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.webhooks[wh.ID] = wh
	return wh, nil
}

func (m *mockWebhookRepo) DeleteWebhook(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.webhooks, id)
	return nil
}

func (m *mockWebhookRepo) IncrementFailureCount(_ context.Context, _ string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureIncrCount++
	return m.failureIncrCount, nil
}

func (m *mockWebhookRepo) ResetFailureCount(_ context.Context, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resetCalled = true
	m.failureIncrCount = 0
	return nil
}

func (m *mockWebhookRepo) DisableWebhook(_ context.Context, _ string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.disableCalled = true
	return nil
}

func (m *mockWebhookRepo) GetActiveWebhooksForEvent(_ context.Context, eventType string) ([]*domain.Webhook, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result []*domain.Webhook
	for _, wh := range m.webhooks {
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

func (m *mockWebhookRepo) CreateDelivery(_ context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deliveries = append(m.deliveries, d)
	return d, nil
}

func (m *mockWebhookRepo) UpdateDelivery(_ context.Context, d *domain.WebhookDelivery) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, existing := range m.deliveries {
		if existing.ID == d.ID {
			m.deliveries[i] = d
			return nil
		}
	}
	m.deliveries = append(m.deliveries, d)
	return nil
}

func (m *mockWebhookRepo) getDeliveries() []*domain.WebhookDelivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*domain.WebhookDelivery, len(m.deliveries))
	copy(cp, m.deliveries)
	return cp
}

func (m *mockWebhookRepo) isResetCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.resetCalled
}

func (m *mockWebhookRepo) isDisableCalled() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.disableCalled
}

func TestDispatcher_SuccessfulDelivery(t *testing.T) {
	var receivedBody []byte
	var receivedSig string
	var receivedEvent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedSig = r.Header.Get("X-Signature-256")
		receivedEvent = r.Header.Get("X-Webhook-Event")
		receivedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	repo := newMockRepo()
	wh := &domain.Webhook{
		ID:         "wh-1",
		URL:        server.URL,
		Secret:     "test-secret",
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo,
		WithBufferSize(10),
		WithHTTPClient(server.Client()),
	)
	d.Start(1)

	event := domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"user_id":"u1"}`),
	}
	d.Dispatch(context.Background(), event)

	// Wait for processing.
	require.NoError(t, d.Close())

	assert.Equal(t, `{"user_id":"u1"}`, string(receivedBody))
	assert.Equal(t, Sign("test-secret", event.Payload), receivedSig)
	assert.Equal(t, domain.WebhookEventUserCreated, receivedEvent)
	assert.True(t, repo.isResetCalled(), "failure count should be reset on success")

	deliveries := repo.getDeliveries()
	require.NotEmpty(t, deliveries)
}

func TestDispatcher_FailedDelivery_RetryLogic(t *testing.T) {
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte("error"))
	}))
	defer server.Close()

	repo := newMockRepo()
	wh := &domain.Webhook{
		ID:         "wh-retry",
		URL:        server.URL,
		Secret:     "secret",
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	// Use very short retry delays for testing.
	d := NewDispatcher(logger, repo,
		WithBufferSize(100),
		WithHTTPClient(server.Client()),
		WithRetryDelays([MaxAttempts]time.Duration{
			1 * time.Millisecond,
			1 * time.Millisecond,
			1 * time.Millisecond,
		}),
	)
	d.Start(1)

	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"retry":"test"}`),
	})

	// Wait for all retry attempts to complete before closing.
	require.Eventually(t, func() bool {
		return callCount.Load() >= int32(MaxAttempts)
	}, 5*time.Second, 5*time.Millisecond, "expected %d delivery attempts", MaxAttempts)

	require.NoError(t, d.Close())
	assert.Equal(t, int32(MaxAttempts), callCount.Load())
}

func TestDispatcher_AutoDisable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("unavailable"))
	}))
	defer server.Close()

	repo := newMockRepo()
	// Set failure count high so one more increment crosses threshold.
	repo.failureIncrCount = domain.DefaultMaxConsecutiveFailures - 1

	wh := &domain.Webhook{
		ID:         "wh-disable",
		URL:        server.URL,
		Secret:     "secret",
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo,
		WithBufferSize(10),
		WithHTTPClient(server.Client()),
		WithRetryDelays([MaxAttempts]time.Duration{
			1 * time.Millisecond,
			1 * time.Millisecond,
			1 * time.Millisecond,
		}),
	)
	d.Start(1)

	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"test":"disable"}`),
	})

	require.NoError(t, d.Close())
	assert.True(t, repo.isDisableCalled(), "webhook should be auto-disabled after threshold")
}

func TestDispatcher_SignatureInHeader(t *testing.T) {
	var headerSig string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		headerSig = r.Header.Get("X-Signature-256")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	repo := newMockRepo()
	secret := "header-test-secret"
	wh := &domain.Webhook{
		ID:         "wh-sig",
		URL:        server.URL,
		Secret:     secret,
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo,
		WithBufferSize(10),
		WithHTTPClient(server.Client()),
	)
	d.Start(1)

	payload := []byte(`{"sig":"check"}`)
	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   payload,
	})
	require.NoError(t, d.Close())

	expected := Sign(secret, payload)
	assert.Equal(t, expected, headerSig)
	assert.True(t, Verify(secret, payload, headerSig))
}

func TestDispatcher_GracefulShutdown(t *testing.T) {
	var delivered atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(10 * time.Millisecond)
		delivered.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	repo := newMockRepo()
	for i := range 5 {
		wh := &domain.Webhook{
			ID:         fmt.Sprintf("wh-%d", i),
			URL:        server.URL,
			Secret:     "secret",
			EventTypes: []string{domain.WebhookEventUserCreated},
			Active:     true,
		}
		_, _ = repo.CreateWebhook(context.Background(), wh)
	}

	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo,
		WithBufferSize(100),
		WithHTTPClient(server.Client()),
	)
	d.Start(2)

	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"shutdown":"test"}`),
	})

	// Close should drain all pending tasks.
	require.NoError(t, d.Close())
	assert.Equal(t, int32(5), delivered.Load(), "all webhooks should be delivered before shutdown")
}

func TestDispatcher_BufferFullDropsEvent(t *testing.T) {
	repo := newMockRepo()
	wh := &domain.Webhook{
		ID:         "wh-full",
		URL:        "http://localhost:1/unreachable",
		Secret:     "s",
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	// Buffer of 1, no workers started = channel fills up.
	d := NewDispatcher(logger, repo, WithBufferSize(1))
	// Don't start workers — channel will fill.

	// First dispatch should succeed (fills buffer).
	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"first":"ok"}`),
	})

	// Second dispatch should be dropped (buffer full).
	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"second":"dropped"}`),
	})

	// Start a worker so Close can drain.
	d.Start(1)
	require.NoError(t, d.Close())
}

func TestDispatcher_DeliveryRecordCreated(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	repo := newMockRepo()
	wh := &domain.Webhook{
		ID:         "wh-record",
		URL:        server.URL,
		Secret:     "secret",
		EventTypes: []string{domain.WebhookEventUserCreated},
		Active:     true,
	}
	_, _ = repo.CreateWebhook(context.Background(), wh)

	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo,
		WithBufferSize(10),
		WithHTTPClient(server.Client()),
	)
	d.Start(1)

	d.Dispatch(context.Background(), domain.WebhookEvent{
		EventType: domain.WebhookEventUserCreated,
		Payload:   []byte(`{"record":"test"}`),
	})
	require.NoError(t, d.Close())

	deliveries := repo.getDeliveries()
	require.Len(t, deliveries, 1)
	assert.Equal(t, "wh-record", deliveries[0].WebhookID)
	assert.Equal(t, domain.WebhookEventUserCreated, deliveries[0].EventType)
	assert.Equal(t, domain.DeliveryStatusSuccess, deliveries[0].Status)
	assert.Equal(t, 200, deliveries[0].ResponseCode)
	assert.NotNil(t, deliveries[0].DeliveredAt)
}

func TestDispatcher_NameAndCloserInterface(t *testing.T) {
	repo := newMockRepo()
	logger := zaptest.NewLogger(t)
	d := NewDispatcher(logger, repo, WithBufferSize(1))
	d.Start(1)

	assert.Equal(t, "webhook-dispatcher", d.Name())
	require.NoError(t, d.Close())

	// Double close should be safe.
	require.NoError(t, d.Close())
}
