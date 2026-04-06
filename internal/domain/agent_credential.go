package domain

import (
	"time"

	"github.com/google/uuid"
)

// AgentCredential type constants.
const (
	CredentialTypeAPIKey     = "api_key"
	CredentialTypeOAuthToken = "oauth_token"
	CredentialTypeCertificate = "certificate"
)

// AgentCredential status constants.
const (
	CredentialStatusActive  = "active"
	CredentialStatusRotated = "rotated"
	CredentialStatusRevoked = "revoked"
)

// AgentCredential represents an encrypted third-party credential managed on behalf of an agent client.
// The raw secret is never stored; only the AES-GCM encrypted blob is persisted.
type AgentCredential struct {
	ID             uuid.UUID  `json:"id"                        db:"id"`
	OwnerClientID  uuid.UUID  `json:"owner_client_id"           db:"owner_client_id"`
	TargetName     string     `json:"target_name"               db:"target_name"`
	CredentialType string     `json:"credential_type"           db:"credential_type"`
	EncryptedBlob  []byte     `json:"-"                         db:"encrypted_blob"`
	Scopes         []string   `json:"scopes"                    db:"scopes"`
	Status         string     `json:"status"                    db:"status"`
	LastRotatedAt  *time.Time `json:"last_rotated_at,omitempty" db:"last_rotated_at"`
	NextRotationAt *time.Time `json:"next_rotation_at,omitempty" db:"next_rotation_at"`
	CreatedAt      time.Time  `json:"created_at"                db:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"                db:"updated_at"`
}

// IsActive returns true when the credential can be brokered.
func (c *AgentCredential) IsActive() bool {
	return c.Status == CredentialStatusActive
}
