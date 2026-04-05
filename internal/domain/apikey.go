package domain

import (
	"time"

	"github.com/google/uuid"
)

// APIKey status constants.
const (
	APIKeyStatusActive  = "active"
	APIKeyStatusRevoked = "revoked"
)

// APIKey represents a long-lived API key bound to a client.
type APIKey struct {
	ID                    uuid.UUID  `json:"id"                        db:"id"`
	ClientID              uuid.UUID  `json:"client_id"                 db:"client_id"`
	Name                  string     `json:"name"                      db:"name"`
	KeyHash               string     `json:"-"                         db:"key_hash"`
	PreviousKeyHash       string     `json:"-"                         db:"previous_key_hash"`
	PreviousKeyExpiresAt  *time.Time `json:"-"                         db:"previous_key_expires_at"`
	Scopes                []string   `json:"scopes"                    db:"scopes"`
	RateLimit             int        `json:"rate_limit"                db:"rate_limit"` // requests per minute
	Status                string     `json:"status"                    db:"status"`
	ExpiresAt             *time.Time `json:"expires_at,omitempty"      db:"expires_at"`
	LastUsedAt            *time.Time `json:"last_used_at,omitempty"    db:"last_used_at"`
	CreatedAt             time.Time  `json:"created_at"                db:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"                db:"updated_at"`
}

// IsExpired returns true if the API key has passed its expiration time.
func (k *APIKey) IsExpired() bool {
	return k.ExpiresAt != nil && time.Now().UTC().After(*k.ExpiresAt)
}

// IsActive returns true if the key status is active and it is not expired.
func (k *APIKey) IsActive() bool {
	return k.Status == APIKeyStatusActive && !k.IsExpired()
}
