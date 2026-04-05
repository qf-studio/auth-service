package domain

import (
	"time"

	"github.com/google/uuid"
)

// API key status constants.
const (
	APIKeyStatusActive  = "active"
	APIKeyStatusRevoked = "revoked"
)

// APIKey represents a machine-to-machine API key bound to a client.
type APIKey struct {
	ID                    uuid.UUID  `json:"id"                       db:"id"`
	ClientID              uuid.UUID  `json:"client_id"                db:"client_id"`
	Name                  string     `json:"name"                     db:"name"`
	KeyHash               string     `json:"-"                        db:"key_hash"`
	PreviousKeyHash       string     `json:"-"                        db:"previous_key_hash"`
	PreviousKeyExpiresAt  *time.Time `json:"-"                        db:"previous_key_expires_at"`
	Scopes                []string   `json:"scopes"                   db:"scopes"`
	RateLimit             int        `json:"rate_limit"               db:"rate_limit"`
	Status                string     `json:"status"                   db:"status"`
	ExpiresAt             *time.Time `json:"expires_at"               db:"expires_at"`
	LastUsedAt            *time.Time `json:"last_used_at"             db:"last_used_at"`
	CreatedAt             time.Time  `json:"created_at"               db:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"               db:"updated_at"`
}

// IsActive returns true if the API key status is active and it has not expired.
func (k *APIKey) IsActive() bool {
	if k.Status != APIKeyStatusActive {
		return false
	}
	if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now().UTC()) {
		return false
	}
	return true
}

// IsExpired returns true if the API key has a set expiry that is in the past.
func (k *APIKey) IsExpired() bool {
	return k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now().UTC())
}
