package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWebhook_Validate(t *testing.T) {
	validWebhook := func() *Webhook {
		return &Webhook{
			ID:         "wh_1",
			URL:        "https://example.com/hook",
			Secret:     "secret123",
			EventTypes: []string{EventUserCreated},
			Active:     true,
		}
	}

	tests := []struct {
		name    string
		modify  func(w *Webhook)
		wantErr bool
		errMsg  string
	}{
		{
			name:    "valid webhook",
			modify:  func(w *Webhook) {},
			wantErr: false,
		},
		{
			name:    "valid with http url",
			modify:  func(w *Webhook) { w.URL = "http://localhost:8080/hook" },
			wantErr: false,
		},
		{
			name:    "valid with multiple event types",
			modify:  func(w *Webhook) { w.EventTypes = []string{EventUserCreated, EventUserDeleted, EventTokenRevoked} },
			wantErr: false,
		},
		{
			name:    "empty url",
			modify:  func(w *Webhook) { w.URL = "" },
			wantErr: true,
			errMsg:  "url",
		},
		{
			name:    "invalid url",
			modify:  func(w *Webhook) { w.URL = "not-a-url" },
			wantErr: true,
			errMsg:  "url",
		},
		{
			name:    "ftp scheme",
			modify:  func(w *Webhook) { w.URL = "ftp://example.com/hook" },
			wantErr: true,
			errMsg:  "scheme",
		},
		{
			name:    "empty secret",
			modify:  func(w *Webhook) { w.Secret = "" },
			wantErr: true,
			errMsg:  "secret",
		},
		{
			name:    "empty event types",
			modify:  func(w *Webhook) { w.EventTypes = nil },
			wantErr: true,
			errMsg:  "event_types",
		},
		{
			name:    "invalid event type",
			modify:  func(w *Webhook) { w.EventTypes = []string{"invalid.event"} },
			wantErr: true,
			errMsg:  "invalid.event",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := validWebhook()
			tt.modify(w)
			err := w.Validate()
			if tt.wantErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestWebhook_IsActive(t *testing.T) {
	w := &Webhook{Active: true}
	assert.True(t, w.IsActive())

	w.Active = false
	assert.False(t, w.IsActive())
}

func TestAllEventTypes(t *testing.T) {
	types := AllEventTypes()
	assert.NotEmpty(t, types)
	// Ensure no duplicates
	seen := make(map[string]bool)
	for _, et := range types {
		assert.False(t, seen[et], "duplicate event type: %s", et)
		seen[et] = true
	}
}
