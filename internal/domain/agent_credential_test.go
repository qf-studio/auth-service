package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestCredentialType_IsValid(t *testing.T) {
	tests := []struct {
		name string
		ct   CredentialType
		want bool
	}{
		{"api_key", CredentialTypeAPIKey, true},
		{"oauth_token", CredentialTypeOAuthToken, true},
		{"certificate", CredentialTypeCertificate, true},
		{"empty", CredentialType(""), false},
		{"unknown", CredentialType("password"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.ct.IsValid())
		})
	}
}

func TestAgentCredential_IsActive(t *testing.T) {
	ac := &AgentCredential{Status: CredentialStatusActive}
	assert.True(t, ac.IsActive())

	ac.Status = CredentialStatusRevoked
	assert.False(t, ac.IsActive())
}

func TestAgentCredential_IsExpired(t *testing.T) {
	t.Run("nil expiry", func(t *testing.T) {
		ac := &AgentCredential{}
		assert.False(t, ac.IsExpired())
	})

	t.Run("future expiry", func(t *testing.T) {
		future := time.Now().Add(time.Hour)
		ac := &AgentCredential{ExpiresAt: &future}
		assert.False(t, ac.IsExpired())
	})

	t.Run("past expiry", func(t *testing.T) {
		past := time.Now().Add(-time.Hour)
		ac := &AgentCredential{ExpiresAt: &past}
		assert.True(t, ac.IsExpired())
	})
}

func TestAgentCredential_NeedsRotation(t *testing.T) {
	ac := &AgentCredential{Status: CredentialStatusRotationPending}
	assert.True(t, ac.NeedsRotation())

	ac.Status = CredentialStatusActive
	assert.False(t, ac.NeedsRotation())
}

func TestValidCredentialStatuses(t *testing.T) {
	assert.True(t, ValidCredentialStatuses[CredentialStatusActive])
	assert.True(t, ValidCredentialStatuses[CredentialStatusExpired])
	assert.True(t, ValidCredentialStatuses[CredentialStatusRevoked])
	assert.True(t, ValidCredentialStatuses[CredentialStatusRotationPending])
	assert.False(t, ValidCredentialStatuses["unknown"])
}

func TestAgentCredential_StructFields(t *testing.T) {
	now := time.Now()
	rotated := now.Add(-24 * time.Hour)
	policy := "30d"
	id := uuid.New()
	ownerID := uuid.New()

	ac := &AgentCredential{
		ID:             id,
		OwnerClientID:  ownerID,
		TargetName:     "github-api",
		CredentialType: CredentialTypeAPIKey,
		EncryptedBlob:  []byte("encrypted-data"),
		Scopes:         []string{"repo", "read:org"},
		Status:         CredentialStatusActive,
		ExpiresAt:      &now,
		LastRotatedAt:  &rotated,
		RotationPolicy: &policy,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	assert.Equal(t, id, ac.ID)
	assert.Equal(t, ownerID, ac.OwnerClientID)
	assert.Equal(t, "github-api", ac.TargetName)
	assert.Equal(t, CredentialTypeAPIKey, ac.CredentialType)
	assert.Equal(t, []byte("encrypted-data"), ac.EncryptedBlob)
	assert.Equal(t, []string{"repo", "read:org"}, ac.Scopes)
	assert.Equal(t, "30d", *ac.RotationPolicy)
}
