package domain

import (
	"time"

	"github.com/google/uuid"
)

// Webhook status constants.
const (
	WebhookStatusActive   = "active"
	WebhookStatusDisabled = "disabled"
)

// Webhook delivery status constants.
const (
	WebhookDeliveryStatusPending   = "pending"
	WebhookDeliveryStatusDelivered = "delivered"
	WebhookDeliveryStatusFailed    = "failed"
)

// MaxWebhookFailures is the number of consecutive failures before a webhook is auto-disabled.
const MaxWebhookFailures = 10

// Webhook represents a webhook subscription that receives event notifications via HTTP POST.
type Webhook struct {
	ID           uuid.UUID `json:"id"            db:"id"`
	TenantID     uuid.UUID `json:"tenant_id"     db:"tenant_id"`
	URL          string    `json:"url"           db:"url"`
	SecretHash   string    `json:"-"             db:"secret_hash"`
	EventTypes   []string  `json:"event_types"   db:"event_types"`
	Active       bool      `json:"active"        db:"active"`
	FailureCount int       `json:"failure_count" db:"failure_count"`
	CreatedAt    time.Time `json:"created_at"    db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"    db:"updated_at"`
}

// WebhookDelivery represents a single delivery attempt for a webhook event.
type WebhookDelivery struct {
	ID           uuid.UUID  `json:"id"                      db:"id"`
	TenantID     uuid.UUID  `json:"tenant_id"               db:"tenant_id"`
	WebhookID    uuid.UUID  `json:"webhook_id"              db:"webhook_id"`
	EventType    string     `json:"event_type"              db:"event_type"`
	Payload      string     `json:"payload"                 db:"payload"`
	Status       string     `json:"status"                  db:"status"`
	ResponseCode *int       `json:"response_code,omitempty" db:"response_code"`
	ResponseBody *string    `json:"response_body,omitempty" db:"response_body"`
	Attempt      int        `json:"attempt"                 db:"attempt"`
	NextRetryAt  *time.Time `json:"next_retry_at,omitempty" db:"next_retry_at"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"  db:"delivered_at"`
	CreatedAt    time.Time  `json:"created_at"              db:"created_at"`
}
