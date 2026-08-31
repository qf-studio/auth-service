package mocks

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testWebhookSecret = "e2e-not-a-real-webhook-secret" //nolint:gosec // fake, test-only

func TestWebhookReceiverMock_ValidSignature(t *testing.T) {
	m := NewWebhookReceiverMock(testWebhookSecret)
	defer m.Close()

	body := []byte(`{"id":"evt-1","event_type":"user.created"}`)
	postWebhook(t, m.URL(), body, sign(testWebhookSecret, body), "user.created")

	deliveries := m.Deliveries()
	require.Len(t, deliveries, 1)
	assert.True(t, deliveries[0].SignatureValid)
	assert.Equal(t, "user.created", deliveries[0].EventType)
	assert.Equal(t, body, deliveries[0].Body)
}

func TestWebhookReceiverMock_InvalidSignature(t *testing.T) {
	m := NewWebhookReceiverMock(testWebhookSecret)
	defer m.Close()

	body := []byte(`{"id":"evt-2","event_type":"user.deleted"}`)
	postWebhook(t, m.URL(), body, "sha256=not-the-right-signature", "user.deleted")

	deliveries := m.Deliveries()
	require.Len(t, deliveries, 1)
	assert.False(t, deliveries[0].SignatureValid)
}

func TestWebhookReceiverMock_MissingSignature(t *testing.T) {
	m := NewWebhookReceiverMock(testWebhookSecret)
	defer m.Close()

	body := []byte(`{"id":"evt-3","event_type":"user.updated"}`)
	postWebhook(t, m.URL(), body, "", "user.updated")

	deliveries := m.Deliveries()
	require.Len(t, deliveries, 1)
	assert.False(t, deliveries[0].SignatureValid)
}

func TestWebhookReceiverMock_MultipleDeliveriesOrdered(t *testing.T) {
	m := NewWebhookReceiverMock(testWebhookSecret)
	defer m.Close()

	for i, evt := range []string{"a", "b", "c"} {
		body := []byte(evt)
		postWebhook(t, m.URL(), body, sign(testWebhookSecret, body), evt)
		require.Len(t, m.Deliveries(), i+1)
	}

	deliveries := m.Deliveries()
	require.Len(t, deliveries, 3)
	assert.Equal(t, "a", deliveries[0].EventType)
	assert.Equal(t, "b", deliveries[1].EventType)
	assert.Equal(t, "c", deliveries[2].EventType)
}

func sign(secret string, body []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

func postWebhook(t *testing.T, baseURL string, body []byte, signature, eventType string) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	if signature != "" {
		req.Header.Set(signatureHeader, signature)
	}
	req.Header.Set(eventTypeHeader, eventType)

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode)
}
