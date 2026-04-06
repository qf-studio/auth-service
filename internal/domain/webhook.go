package domain

import (
	"fmt"
	"net/url"
	"time"
)

// Webhook event types.
const (
	EventUserCreated         = "user.created"
	EventUserUpdated         = "user.updated"
	EventUserDeleted         = "user.deleted"
	EventUserLocked          = "user.locked"
	EventUserUnlocked        = "user.unlocked"
	EventTokenIssued         = "token.issued"
	EventTokenRevoked        = "token.revoked"
	EventClientCreated       = "client.created"
	EventClientUpdated       = "client.updated"
	EventClientDeleted       = "client.deleted"
	EventPermissionChanged   = "permission.changed"
	EventMFAEnabled          = "mfa.enabled"
	EventMFADisabled         = "mfa.disabled"
	EventLoginSuccess        = "login.success"
	EventLoginFailed         = "login.failed"
)

// AllEventTypes returns all supported webhook event types.
func AllEventTypes() []string {
	return []string{
		EventUserCreated, EventUserUpdated, EventUserDeleted,
		EventUserLocked, EventUserUnlocked,
		EventTokenIssued, EventTokenRevoked,
		EventClientCreated, EventClientUpdated, EventClientDeleted,
		EventPermissionChanged,
		EventMFAEnabled, EventMFADisabled,
		EventLoginSuccess, EventLoginFailed,
	}
}

// Webhook delivery statuses.
const (
	DeliveryStatusPending   = "pending"
	DeliveryStatusDelivered = "delivered"
	DeliveryStatusFailed    = "failed"
)

// Webhook represents a registered webhook endpoint.
type Webhook struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	Secret       string    `json:"-"`
	EventTypes   []string  `json:"event_types"`
	Active       bool      `json:"active"`
	FailureCount int       `json:"failure_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// WebhookDelivery represents a single delivery attempt for a webhook.
type WebhookDelivery struct {
	ID           string     `json:"id"`
	WebhookID    string     `json:"webhook_id"`
	EventType    string     `json:"event_type"`
	Payload      []byte     `json:"payload"`
	Status       string     `json:"status"`
	ResponseCode *int       `json:"response_code,omitempty"`
	Attempt      int        `json:"attempt"`
	NextRetryAt  *time.Time `json:"next_retry_at,omitempty"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// Validate checks that the webhook has valid fields.
func (w *Webhook) Validate() error {
	if w.URL == "" {
		return fmt.Errorf("webhook url: %w", ErrValidationRequired)
	}
	u, err := url.ParseRequestURI(w.URL)
	if err != nil {
		return fmt.Errorf("webhook url: %w", ErrValidationInvalid)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("webhook url scheme must be http or https: %w", ErrValidationInvalid)
	}
	if w.Secret == "" {
		return fmt.Errorf("webhook secret: %w", ErrValidationRequired)
	}
	if len(w.EventTypes) == 0 {
		return fmt.Errorf("webhook event_types: %w", ErrValidationRequired)
	}
	valid := validEventTypes()
	for _, et := range w.EventTypes {
		if !valid[et] {
			return fmt.Errorf("webhook event_type %q: %w", et, ErrValidationInvalid)
		}
	}
	return nil
}

// IsActive returns true if the webhook is active.
func (w *Webhook) IsActive() bool {
	return w.Active
}

func validEventTypes() map[string]bool {
	m := make(map[string]bool, len(AllEventTypes()))
	for _, et := range AllEventTypes() {
		m[et] = true
	}
	return m
}
