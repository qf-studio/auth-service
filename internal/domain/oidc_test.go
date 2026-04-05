package domain

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestConsentState_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		state    ConsentState
		expected bool
	}{
		{"pending is valid", ConsentStatePending, true},
		{"accepted is valid", ConsentStateAccepted, true},
		{"rejected is valid", ConsentStateRejected, true},
		{"revoked is valid", ConsentStateRevoked, true},
		{"empty is invalid", ConsentState(""), false},
		{"unknown is invalid", ConsentState("unknown"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, tt.state.IsValid())
		})
	}
}

func TestAuthorizationCode_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt time.Time
		expected  bool
	}{
		{"future expiry", time.Now().Add(5 * time.Minute), false},
		{"past expiry", time.Now().Add(-5 * time.Minute), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthorizationCode{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.expected, ac.IsExpired())
		})
	}
}

func TestAuthorizationCode_IsUsed(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		usedAt   *time.Time
		expected bool
	}{
		{"not used", nil, false},
		{"used", &now, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ac := &AuthorizationCode{UsedAt: tt.usedAt}
			assert.Equal(t, tt.expected, ac.IsUsed())
		})
	}
}

func TestAuthorizationCode_FieldDefaults(t *testing.T) {
	ac := AuthorizationCode{
		ID:        uuid.New(),
		ClientID:  uuid.New(),
		UserID:    "user-123",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	assert.Empty(t, ac.CodeChallenge)
	assert.Empty(t, ac.CodeChallengeMethod)
	assert.Empty(t, ac.Nonce)
	assert.Nil(t, ac.UsedAt)
}

func TestConsentSession_StateTransitions(t *testing.T) {
	cs := ConsentSession{
		ID:              uuid.New(),
		ClientID:        uuid.New(),
		UserID:          "user-123",
		RequestedScopes: []string{"openid", "profile"},
		State:           ConsentStatePending,
	}

	assert.Equal(t, ConsentStatePending, cs.State)
	assert.Empty(t, cs.GrantedScopes)

	// Simulate acceptance.
	cs.State = ConsentStateAccepted
	cs.GrantedScopes = []string{"openid", "profile"}
	assert.Equal(t, ConsentStateAccepted, cs.State)
	assert.Equal(t, []string{"openid", "profile"}, cs.GrantedScopes)
}

func TestClientApprovalStatusConstants(t *testing.T) {
	assert.Equal(t, "pending", ClientApprovalPending)
	assert.Equal(t, "approved", ClientApprovalApproved)
	assert.Equal(t, "rejected", ClientApprovalRejected)
}
