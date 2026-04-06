package domain

import (
	"time"

	"github.com/google/uuid"
)

// CredentialType represents the kind of stored credential.
type CredentialType string

const (
	CredentialTypeAPIKey     CredentialType = "api_key"
	CredentialTypeOAuthToken CredentialType = "oauth_token"
	CredentialTypeCertificate CredentialType = "certificate"
)

// IsValid returns true if the CredentialType is a recognised value.
func (ct CredentialType) IsValid() bool {
	switch ct {
	case CredentialTypeAPIKey, CredentialTypeOAuthToken, CredentialTypeCertificate:
		return true
	}
	return false
}

// Credential status constants.
const (
	CredentialStatusActive          = "active"
	CredentialStatusExpired         = "expired"
	CredentialStatusRevoked         = "revoked"
	CredentialStatusRotationPending = "rotation_pending"
)

// ValidCredentialStatuses lists all recognised credential statuses.
var ValidCredentialStatuses = map[string]bool{
	CredentialStatusActive:          true,
	CredentialStatusExpired:         true,
	CredentialStatusRevoked:         true,
	CredentialStatusRotationPending: true,
}

// AgentCredential represents an encrypted credential stored in the vault
// on behalf of an agent or service client.
type AgentCredential struct {
	ID             uuid.UUID      `json:"id"               db:"id"`
	OwnerClientID  uuid.UUID      `json:"owner_client_id"  db:"owner_client_id"`
	TargetName     string         `json:"target_name"      db:"target_name"`
	CredentialType CredentialType `json:"credential_type"  db:"credential_type"`
	EncryptedBlob  []byte         `json:"-"                db:"encrypted_blob"`
	Scopes         []string       `json:"scopes"           db:"scopes"`
	Status         string         `json:"status"           db:"status"`
	ExpiresAt      *time.Time     `json:"expires_at,omitempty"      db:"expires_at"`
	LastRotatedAt  *time.Time     `json:"last_rotated_at,omitempty" db:"last_rotated_at"`
	RotationPolicy *string        `json:"rotation_policy,omitempty" db:"rotation_policy"`
	CreatedAt      time.Time      `json:"created_at"       db:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"       db:"updated_at"`
}

// IsActive returns true if the credential status is active.
func (ac *AgentCredential) IsActive() bool {
	return ac.Status == CredentialStatusActive
}

// IsExpired returns true if the credential has passed its expiration time.
func (ac *AgentCredential) IsExpired() bool {
	if ac.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*ac.ExpiresAt)
}

// NeedsRotation returns true if the credential status indicates a pending rotation.
func (ac *AgentCredential) NeedsRotation() bool {
	return ac.Status == CredentialStatusRotationPending
}
