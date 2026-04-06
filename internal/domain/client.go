package domain

import (
	"time"

	"github.com/google/uuid"
)

// ClientType represents the kind of OAuth2 client.
type ClientType string

const (
	ClientTypeUser    ClientType = "user"
	ClientTypeService ClientType = "service"
	ClientTypeAgent   ClientType = "agent"
)

// IsValid returns true if the ClientType is a recognised value.
// It delegates to ValidClientTypes (defined in admin.go) for a single source of truth.
func (ct ClientType) IsValid() bool {
	return ValidClientTypes[string(ct)]
}

// Client status constants.
const (
	ClientStatusActive    = "active"
	ClientStatusSuspended = "suspended"
	ClientStatusRevoked   = "revoked"
)

// Client represents an OAuth2 client (service or AI agent) in the system.
type Client struct {
	ID                      uuid.UUID  `json:"id"                          db:"id"`
	TenantID                string     `json:"tenant_id"                   db:"tenant_id"`
	Name                    string     `json:"name"                        db:"name"`
	ClientType              ClientType `json:"client_type"                 db:"client_type"`
	SecretHash              string     `json:"-"                           db:"secret_hash"`
	PreviousSecretHash      string     `json:"-"                           db:"previous_secret_hash"`
	PreviousSecretExpiresAt *time.Time `json:"-"                           db:"previous_secret_expires_at"`
	Scopes                  []string   `json:"scopes"                      db:"scopes"`
	Owner                   string     `json:"owner"                       db:"owner"`
	AccessTokenTTL          int        `json:"access_token_ttl"            db:"access_token_ttl"` // seconds
	Status                  string     `json:"status"                      db:"status"`
	CreatedAt               time.Time  `json:"created_at"                  db:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"                  db:"updated_at"`
	LastUsedAt              *time.Time `json:"last_used_at"                db:"last_used_at"`
}

// AccessTokenDuration returns the access token TTL as a time.Duration.
func (c *Client) AccessTokenDuration() time.Duration {
	return time.Duration(c.AccessTokenTTL) * time.Second
}

// IsActive returns true if the client status is active.
func (c *Client) IsActive() bool {
	return c.Status == ClientStatusActive
}
