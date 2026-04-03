package domain

import (
	"time"

	"github.com/google/uuid"
)

// ClientType represents the kind of OAuth2 client.
type ClientType string

const (
	ClientTypeService ClientType = "service"
	ClientTypeAgent   ClientType = "agent"
)

// ValidClientTypes enumerates all accepted ClientType values.
var ValidClientTypes = []ClientType{ClientTypeService, ClientTypeAgent}

// IsValid returns true if the ClientType is a recognised value.
func (ct ClientType) IsValid() bool {
	for _, v := range ValidClientTypes {
		if ct == v {
			return true
		}
	}
	return false
}

// Client status constants.
const (
	ClientStatusActive    = "active"
	ClientStatusSuspended = "suspended"
	ClientStatusRevoked   = "revoked"
)

// Client represents an OAuth2 client (service or AI agent) in the system.
type Client struct {
	ID             uuid.UUID  `json:"id"               db:"id"`
	Name           string     `json:"name"             db:"name"`
	ClientType     ClientType `json:"client_type"      db:"client_type"`
	SecretHash     string     `json:"-"                db:"secret_hash"`
	Scopes         []string   `json:"scopes"           db:"scopes"`
	Owner          string     `json:"owner"            db:"owner"`
	AccessTokenTTL int        `json:"access_token_ttl" db:"access_token_ttl"` // seconds
	Status         string     `json:"status"           db:"status"`
	CreatedAt      time.Time  `json:"created_at"       db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"       db:"updated_at"`
	LastUsedAt     *time.Time `json:"last_used_at"     db:"last_used_at"`
}

// AccessTokenDuration returns the access token TTL as a time.Duration.
func (c *Client) AccessTokenDuration() time.Duration {
	return time.Duration(c.AccessTokenTTL) * time.Second
}

// IsActive returns true if the client status is active.
func (c *Client) IsActive() bool {
	return c.Status == ClientStatusActive
}
