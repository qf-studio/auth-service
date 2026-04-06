package domain

import (
	"time"

	"github.com/google/uuid"
)

// Credential type constants identify what kind of secret is stored in the vault.
const (
	CredentialTypeAPIKey   = "api_key"
	CredentialTypeOAuth    = "oauth_token"
	CredentialTypeCert     = "certificate"
	CredentialTypePassword = "password"
)

// Credential status constants.
const (
	CredentialStatusActive  = "active"
	CredentialStatusRevoked = "revoked"
	CredentialStatusExpired = "expired"
)

// AgentCredential represents an encrypted credential stored in the vault
// that an agent (AI service or system client) can access via the broker.
type AgentCredential struct {
	ID               uuid.UUID `json:"id"                db:"id"`
	AgentClientID    uuid.UUID `json:"agent_client_id"   db:"agent_client_id"`
	TargetService    string    `json:"target_service"    db:"target_service"`
	EncryptedPayload []byte    `json:"-"                 db:"encrypted_payload"`
	CredentialType   string    `json:"credential_type"   db:"credential_type"`
	Scopes           []string  `json:"scopes"            db:"scopes"`
	Status           string    `json:"status"            db:"status"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty" db:"expires_at"`
	CreatedAt        time.Time `json:"created_at"        db:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"        db:"updated_at"`
}

// IsActive returns true if the credential is active and not expired.
func (c *AgentCredential) IsActive() bool {
	if c.Status != CredentialStatusActive {
		return false
	}
	if c.ExpiresAt != nil && c.ExpiresAt.Before(time.Now()) {
		return false
	}
	return true
}
