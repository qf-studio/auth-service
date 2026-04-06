package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestConsentState_IsValid(t *testing.T) {
	tests := []struct {
		state ConsentState
		valid bool
	}{
		{ConsentStatePending, true},
		{ConsentStateAccepted, true},
		{ConsentStateRejected, true},
		{ConsentStateRevoked, true},
		{ConsentState("invalid"), false},
		{ConsentState(""), false},
	}
	for _, tt := range tests {
		t.Run(string(tt.state), func(t *testing.T) {
			assert.Equal(t, tt.valid, tt.state.IsValid())
		})
	}
}

func TestAuthorizationCode_IsExpired(t *testing.T) {
	ac := &AuthorizationCode{
		ExpiresAt: time.Now().UTC().Add(-1 * time.Minute),
	}
	assert.True(t, ac.IsExpired())

	ac.ExpiresAt = time.Now().UTC().Add(10 * time.Minute)
	assert.False(t, ac.IsExpired())
}

func TestAuthorizationCode_IsUsed(t *testing.T) {
	ac := &AuthorizationCode{}
	assert.False(t, ac.IsUsed())

	now := time.Now().UTC()
	ac.UsedAt = &now
	assert.True(t, ac.IsUsed())
}

func TestAuthorizationCode_Fields(t *testing.T) {
	now := time.Now().UTC()
	clientID := uuid.New()
	ac := AuthorizationCode{
		CodeHash:            "hash123",
		ClientID:            clientID,
		UserID:              "u-1",
		RedirectURI:         "https://example.com/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       "challenge",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce",
		ExpiresAt:           now.Add(10 * time.Minute),
		CreatedAt:           now,
	}
	assert.Equal(t, "hash123", ac.CodeHash)
	assert.Equal(t, clientID, ac.ClientID)
	assert.Equal(t, "u-1", ac.UserID)
	assert.Equal(t, "https://example.com/cb", ac.RedirectURI)
	assert.Equal(t, []string{"openid"}, ac.Scopes)
	assert.Equal(t, "S256", ac.CodeChallengeMethod)
}

func TestConsentSession_Fields(t *testing.T) {
	now := time.Now().UTC()
	clientID := uuid.New()
	s := ConsentSession{
		Challenge:        "challenge-abc",
		Verifier:         "verifier-xyz",
		ClientID:         clientID,
		UserID:           "u-1",
		RequestedScopes:  []string{"openid", "profile"},
		GrantedScopes:    []string{"openid"},
		State:            ConsentStatePending,
		LoginSessionID:   "session-123",
		EncryptedPayload: []byte("data"),
		CreatedAt:        now,
		UpdatedAt:        now,
	}
	assert.Equal(t, "challenge-abc", s.Challenge)
	assert.Equal(t, clientID, s.ClientID)
	assert.Equal(t, ConsentStatePending, s.State)
	assert.Equal(t, []string{"openid", "profile"}, s.RequestedScopes)
}

func TestIDTokenClaims_Fields(t *testing.T) {
	claims := IDTokenClaims{
		Subject:       "u-1",
		Issuer:        "https://auth.example.com",
		Audience:      "client-1",
		ExpiresAt:     1700000000,
		IssuedAt:      1699996400,
		Nonce:         "nonce",
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}
	assert.Equal(t, "u-1", claims.Subject)
	assert.Equal(t, "https://auth.example.com", claims.Issuer)
	assert.True(t, claims.EmailVerified)
}

func TestUserInfoResponse_Fields(t *testing.T) {
	info := UserInfoResponse{
		Subject:       "u-1",
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
		UpdatedAt:     1700000000,
	}
	assert.Equal(t, "u-1", info.Subject)
	assert.Equal(t, "user@example.com", info.Email)
	assert.True(t, info.EmailVerified)
}

func TestApprovalStatusConstants(t *testing.T) {
	assert.Equal(t, "pending", ApprovalStatusPending)
	assert.Equal(t, "approved", ApprovalStatusApproved)
	assert.Equal(t, "rejected", ApprovalStatusRejected)
}
