package domain

import "time"

// Webhook event types that can trigger delivery.
const (
	WebhookEventUserCreated       = "user.created"
	WebhookEventUserUpdated       = "user.updated"
	WebhookEventUserDeleted       = "user.deleted"
	WebhookEventUserLocked        = "user.locked"
	WebhookEventUserUnlocked      = "user.unlocked"
	WebhookEventClientCreated     = "client.created"
	WebhookEventClientUpdated     = "client.updated"
	WebhookEventClientDeleted     = "client.deleted"
	WebhookEventTokenRevoked      = "token.revoked"
	WebhookEventLoginSuccess      = "login.success"
	WebhookEventLoginFailure      = "login.failure"
	WebhookEventPasswordChanged   = "password.changed"
	WebhookEventPasswordReset     = "password.reset"
	WebhookEventAPIKeyCreated     = "apikey.created"
	WebhookEventAPIKeyRevoked     = "apikey.revoked"
	WebhookEventPermissionChanged = "permission.changed"
)

// Delivery status constants.
const (
	DeliveryStatusPending   = "pending"
	DeliveryStatusSuccess   = "success"
	DeliveryStatusFailed    = "failed"
	DeliveryStatusRetrying  = "retrying"
	DeliveryStatusAbandoned = "abandoned"
)

// DefaultMaxConsecutiveFailures is the failure count after which a webhook is auto-disabled.
const DefaultMaxConsecutiveFailures = 10

// Webhook represents a registered webhook endpoint.
type Webhook struct {
	ID           string
	URL          string
	Secret       string // HMAC-SHA256 signing secret
	EventTypes   []string
	Active       bool
	FailureCount int
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// WebhookDelivery records a single delivery attempt for a webhook.
type WebhookDelivery struct {
	ID             string
	WebhookID      string
	EventType      string
	Payload        []byte
	Status         string
	ResponseCode   int
	ResponseBody   string
	Attempt        int
	NextRetryAt    *time.Time
	DeliveredAt    *time.Time
	DurationMs     int
	CreatedAt      time.Time
}

// WebhookEvent is the envelope dispatched to the webhook worker pool.
type WebhookEvent struct {
	EventType string
	Payload   []byte
}
