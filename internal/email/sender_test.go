package email

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestConsoleSender_AllMethodsSucceed(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sender := NewConsoleSender(logger)
	ctx := context.Background()

	assert.NoError(t, sender.SendVerificationEmail(ctx, "test@example.com", "token123"))
	assert.NoError(t, sender.SendPasswordReset(ctx, "test@example.com", "token456"))
	assert.NoError(t, sender.SendAccountLockout(ctx, "test@example.com", "too many attempts"))
	assert.NoError(t, sender.SendMFAEnrollment(ctx, "test@example.com"))
}

func TestNopSender_AllMethodsSucceed(t *testing.T) {
	sender := NopSender{}
	ctx := context.Background()

	assert.NoError(t, sender.SendVerificationEmail(ctx, "test@example.com", "token123"))
	assert.NoError(t, sender.SendPasswordReset(ctx, "test@example.com", "token456"))
	assert.NoError(t, sender.SendAccountLockout(ctx, "test@example.com", "reason"))
	assert.NoError(t, sender.SendMFAEnrollment(ctx, "test@example.com"))
}

func TestHTTPSender_SendVerificationEmail(t *testing.T) {
	var received emailRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/send", r.URL.Path)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "Bearer test-api-key", r.Header.Get("Authorization"))

		err := json.NewDecoder(r.Body).Decode(&received)
		require.NoError(t, err)

		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	sender := NewHTTPSender(server.URL, "test-api-key", "noreply@test.com", logger)

	err := sender.SendVerificationEmail(context.Background(), "user@example.com", "verify-token-123")
	require.NoError(t, err)

	assert.Equal(t, "noreply@test.com", received.From)
	assert.Equal(t, "user@example.com", received.To)
	assert.Equal(t, "Verify your email address", received.Subject)
	assert.Contains(t, received.Body, "verify-token-123")
}

func TestHTTPSender_SendPasswordReset(t *testing.T) {
	var received emailRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		err := json.NewDecoder(r.Body).Decode(&received)
		require.NoError(t, err)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	sender := NewHTTPSender(server.URL, "test-api-key", "noreply@test.com", logger)

	err := sender.SendPasswordReset(context.Background(), "user@example.com", "reset-token-456")
	require.NoError(t, err)

	assert.Equal(t, "user@example.com", received.To)
	assert.Equal(t, "Reset your password", received.Subject)
	assert.Contains(t, received.Body, "reset-token-456")
}

func TestHTTPSender_ErrorResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"service unavailable"}`))
	}))
	defer server.Close()

	logger, _ := zap.NewDevelopment()
	sender := NewHTTPSender(server.URL, "test-api-key", "noreply@test.com", logger)

	err := sender.SendVerificationEmail(context.Background(), "user@example.com", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
}

func TestHTTPSender_ConnectionError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	sender := NewHTTPSender("http://localhost:1", "key", "noreply@test.com", logger)

	err := sender.SendVerificationEmail(context.Background(), "user@example.com", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "send email")
}
