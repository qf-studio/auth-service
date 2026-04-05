package domain

import (
	"time"

	"github.com/google/uuid"
)

// APIKeyStatus constants.
const (
	APIKeyStatusActive  = "active"
	APIKeyStatusRevoked = "revoked"
)

// APIKey represents an API key for service-to-service or agent authentication.
type APIKey struct {
	ID                      uuid.UUID  `json:"id"                          db:"id"`
	ClientID                uuid.UUID  `json:"client_id"                   db:"client_id"`
	Name                    string     `json:"name"                        db:"name"`
	KeyHash                 string     `json:"-"                           db:"key_hash"`
	PreviousKeyHash         string     `json:"-"                           db:"previous_key_hash"`
	PreviousKeyExpiresAt    *time.Time `json:"-"                           db:"previous_key_expires_at"`
	KeyPrefix               string     `json:"key_prefix"                  db:"key_prefix"`
	Scopes                  []string   `json:"scopes"                      db:"scopes"`
	RateLimit               int        `json:"rate_limit"                  db:"rate_limit"`
	Status                  string     `json:"status"                      db:"status"`
	ExpiresAt               *time.Time `json:"expires_at,omitempty"        db:"expires_at"`
	LastUsedAt              *time.Time `json:"last_used_at,omitempty"      db:"last_used_at"`
	CreatedAt               time.Time  `json:"created_at"                  db:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"                  db:"updated_at"`
}

// IsActive returns true if the API key status is active and not expired.
func (k *APIKey) IsActive() bool {
	if k.Status != APIKeyStatusActive {
		return false
	}
	if k.ExpiresAt != nil && k.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
