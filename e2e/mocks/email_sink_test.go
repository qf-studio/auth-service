package mocks

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailSinkMock_CapturesMessage(t *testing.T) {
	m := NewEmailSinkMock()
	defer m.Close()

	postSend(t, m.URL(), sendEmailRequest{
		From:      "noreply@example.com",
		To:        []string{"user@example.com"},
		Subject:   "Verify your email",
		Body:      "Use the link below:\n\nhttps://app.example.com/verify?token=abc123\n\nExpires soon.",
		Transport: "default",
	})

	messages := m.Messages()
	require.Len(t, messages, 1)
	assert.Equal(t, "noreply@example.com", messages[0].From)
	assert.Equal(t, "user@example.com", messages[0].To)
	assert.Equal(t, "Verify your email", messages[0].Subject)

	toUser := m.MessagesTo("user@example.com")
	require.Len(t, toUser, 1)

	toOther := m.MessagesTo("nobody@example.com")
	assert.Empty(t, toOther)
}

func TestExtractToken(t *testing.T) {
	tests := []struct {
		name      string
		body      string
		wantToken string
		wantOK    bool
	}{
		{
			name:      "verify link",
			body:      "Use the link below to verify your email address:\n\nhttps://app.example.com/verify-email?token=deadbeef\n\nThis link expires in 24h0m0s.",
			wantToken: "deadbeef",
			wantOK:    true,
		},
		{
			name:      "reset link with trailing query param",
			body:      "Reset here: https://app.example.com/reset?foo=bar&token=abc-123&baz=qux",
			wantToken: "abc-123",
			wantOK:    true,
		},
		{
			name:   "no token",
			body:   "There is no link in this message.",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, ok := ExtractToken(tt.body)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantToken, token)
			}
		})
	}
}

func TestEmailSinkMock_WaitForToken_Success(t *testing.T) {
	m := NewEmailSinkMock()
	defer m.Close()

	go func() {
		time.Sleep(20 * time.Millisecond)
		postSend(t, m.URL(), sendEmailRequest{
			From:    "noreply@example.com",
			To:      []string{"user@example.com"},
			Subject: "Reset your password",
			Body:    "Link: https://app.example.com/reset?token=xyz789",
		})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	token, err := m.WaitForToken(ctx, "user@example.com", time.Second)
	require.NoError(t, err)
	assert.Equal(t, "xyz789", token)
}

func TestEmailSinkMock_WaitForToken_Timeout(t *testing.T) {
	m := NewEmailSinkMock()
	defer m.Close()

	_, err := m.WaitForToken(context.Background(), "nobody@example.com", 50*time.Millisecond)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nobody@example.com")
}

func postSend(t *testing.T, baseURL string, req sendEmailRequest) {
	t.Helper()
	body, err := json.Marshal(req)
	require.NoError(t, err)

	httpReq, err := http.NewRequestWithContext(context.Background(), http.MethodPost, baseURL+"/send-email", bytes.NewReader(body))
	require.NoError(t, err)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(httpReq)
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusAccepted, resp.StatusCode)
}
