package email_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/qf-studio/auth-service/internal/email"
)

// ── ConsoleSender ─────────────────────────────────────────────────────────────

func TestConsoleSender_Send(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	s := email.NewConsoleSender(logger)
	msg := email.Message{
		To:      "alice@example.com",
		Subject: "Hello",
		Body:    "World",
	}

	err := s.Send(context.Background(), msg)
	require.NoError(t, err)

	require.Equal(t, 1, logs.Len())
	entry := logs.All()[0]
	assert.Equal(t, "email (console)", entry.Message)

	fields := map[string]string{}
	for _, f := range entry.Context {
		fields[f.Key] = f.String
	}
	assert.Equal(t, "alice@example.com", fields["to"])
	assert.Equal(t, "Hello", fields["subject"])
	assert.Equal(t, "World", fields["body"])
}

// ── HTTPSender ────────────────────────────────────────────────────────────────

func TestHTTPSender_Send_success(t *testing.T) {
	var capturedReq struct {
		From      string   `json:"from"`
		To        []string `json:"to"`
		Subject   string   `json:"subject"`
		Body      string   `json:"body"`
		Transport string   `json:"transport"`
	}
	var capturedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "/send-email", r.URL.Path)

		capturedAuth = r.Header.Get("Authorization")

		err := json.NewDecoder(r.Body).Decode(&capturedReq)
		require.NoError(t, err)

		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"status":"Email queued successfully"}`))
	}))
	defer srv.Close()

	s := email.NewHTTPSender(srv.URL, "test-api-key", "noreply@example.com", srv.Client())
	msg := email.Message{
		To:      "bob@example.com",
		Subject: "Welcome",
		Body:    "Hello Bob",
	}

	err := s.Send(context.Background(), msg)
	require.NoError(t, err)

	assert.Equal(t, "Bearer test-api-key", capturedAuth)
	assert.Equal(t, "noreply@example.com", capturedReq.From)
	assert.Equal(t, []string{"bob@example.com"}, capturedReq.To)
	assert.Equal(t, "Welcome", capturedReq.Subject)
	assert.Equal(t, "Hello Bob", capturedReq.Body)
	assert.Equal(t, "default", capturedReq.Transport)
}

func TestHTTPSender_Send_serverError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal error"}`))
	}))
	defer srv.Close()

	s := email.NewHTTPSender(srv.URL, "key", "from@example.com", srv.Client())
	err := s.Send(context.Background(), email.Message{To: "x@x.com", Subject: "s", Body: "b"})

	require.Error(t, err)
	assert.Contains(t, err.Error(), "500")
}

func TestHTTPSender_Send_connectionError(t *testing.T) {
	// Point at a server that is already closed.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	srv.Close()

	s := email.NewHTTPSender(srv.URL, "key", "from@example.com", srv.Client())
	err := s.Send(context.Background(), email.Message{To: "x@x.com", Subject: "s", Body: "b"})

	require.Error(t, err)
}

func TestHTTPSender_Send_non2xxTreatedAsError(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"400 bad request", http.StatusBadRequest},
		{"401 unauthorized", http.StatusUnauthorized},
		{"404 not found", http.StatusNotFound},
		{"503 service unavailable", http.StatusServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer srv.Close()

			s := email.NewHTTPSender(srv.URL, "key", "from@example.com", srv.Client())
			err := s.Send(context.Background(), email.Message{To: "x@x.com", Subject: "s", Body: "b"})
			require.Error(t, err)
		})
	}
}
