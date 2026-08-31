package mocks

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
)

// signatureHeader/eventTypeHeader mirror internal/webhook.Dispatcher's
// delivery headers.
const (
	signatureHeader = "X-Signature-256"
	eventTypeHeader = "X-Webhook-Event"
)

// WebhookDelivery is a captured webhook POST.
type WebhookDelivery struct {
	EventType      string
	Headers        http.Header
	Body           []byte
	SignatureValid bool
}

// WebhookReceiverMock fakes a subscriber endpoint for
// internal/webhook.Dispatcher deliveries: it records every POST and
// independently verifies the X-Signature-256 HMAC-SHA256 header against the
// secret the webhook subscription was created with, the same way a real
// third-party receiver would.
type WebhookReceiverMock struct {
	server *httptest.Server
	secret string

	mu         sync.Mutex
	deliveries []WebhookDelivery
}

// NewWebhookReceiverMock starts the fake receiver, verifying deliveries
// against secret (the webhook subscription's signing secret). Callers must
// Close it when done.
func NewWebhookReceiverMock(secret string) *WebhookReceiverMock {
	m := &WebhookReceiverMock{secret: secret}
	mux := http.NewServeMux()
	mux.HandleFunc("/", m.handle)
	m.server = httptest.NewServer(mux)
	return m
}

// URL returns the mock's base URL (no trailing slash), suitable as a
// webhook subscription's delivery URL.
func (m *WebhookReceiverMock) URL() string { return m.server.URL }

// Port returns the TCP port the mock is listening on, for wiring container
// host-port access.
func (m *WebhookReceiverMock) Port() (int, error) { return serverPort(m.server) }

// Close shuts down the underlying httptest.Server.
func (m *WebhookReceiverMock) Close() { m.server.Close() }

func (m *WebhookReceiverMock) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	delivery := WebhookDelivery{
		EventType:      r.Header.Get(eventTypeHeader),
		Headers:        r.Header.Clone(),
		Body:           body,
		SignatureValid: m.verifySignature(body, r.Header.Get(signatureHeader)),
	}

	m.mu.Lock()
	m.deliveries = append(m.deliveries, delivery)
	m.mu.Unlock()

	w.WriteHeader(http.StatusOK)
}

// verifySignature mirrors internal/webhook.Dispatcher's HMAC-SHA256
// "sha256=<hex>" signature scheme.
func (m *WebhookReceiverMock) verifySignature(body []byte, header string) bool {
	if m.secret == "" || header == "" {
		return false
	}
	mac := hmac.New(sha256.New, []byte(m.secret))
	mac.Write(body)
	want := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(want), []byte(header))
}

// Deliveries returns a snapshot of received deliveries, in receipt order.
func (m *WebhookReceiverMock) Deliveries() []WebhookDelivery {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]WebhookDelivery, len(m.deliveries))
	copy(out, m.deliveries)
	return out
}
