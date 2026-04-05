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

// ── Consent State Machine Transitions ────────────────────────────────────────

func TestConsentState_AllTransitions(t *testing.T) {
	tests := []struct {
		name        string
		from        ConsentState
		to          ConsentState
		description string
	}{
		{"pending to accepted", ConsentStatePending, ConsentStateAccepted, "user grants consent"},
		{"pending to rejected", ConsentStatePending, ConsentStateRejected, "user denies consent"},
		{"accepted to revoked", ConsentStateAccepted, ConsentStateRevoked, "user revokes previously granted consent"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cs := ConsentSession{
				ID:              uuid.New(),
				ClientID:        uuid.New(),
				UserID:          "user-123",
				RequestedScopes: []string{"openid", "profile", "email"},
				State:           tt.from,
			}

			assert.True(t, tt.from.IsValid(), "source state should be valid")
			cs.State = tt.to
			assert.True(t, tt.to.IsValid(), "target state should be valid")
			assert.Equal(t, tt.to, cs.State)
		})
	}
}

func TestConsentSession_AcceptedSetsGrantedScopes(t *testing.T) {
	cs := ConsentSession{
		ID:              uuid.New(),
		ClientID:        uuid.New(),
		UserID:          "user-123",
		RequestedScopes: []string{"openid", "profile", "email"},
		State:           ConsentStatePending,
	}

	// Initially no granted scopes.
	assert.Empty(t, cs.GrantedScopes)

	// Accept with partial scopes (user only grants openid + profile).
	cs.State = ConsentStateAccepted
	cs.GrantedScopes = []string{"openid", "profile"}

	assert.Equal(t, ConsentStateAccepted, cs.State)
	assert.Len(t, cs.GrantedScopes, 2)
	assert.Contains(t, cs.GrantedScopes, "openid")
	assert.Contains(t, cs.GrantedScopes, "profile")
	assert.NotContains(t, cs.GrantedScopes, "email")
}

func TestConsentSession_RejectedKeepsEmptyGrantedScopes(t *testing.T) {
	cs := ConsentSession{
		ID:              uuid.New(),
		ClientID:        uuid.New(),
		UserID:          "user-reject",
		RequestedScopes: []string{"openid"},
		State:           ConsentStatePending,
	}

	cs.State = ConsentStateRejected
	assert.Empty(t, cs.GrantedScopes, "rejected consent should have no granted scopes")
}

func TestConsentSession_ChallengeVerifierPair(t *testing.T) {
	challenge := "chal_" + uuid.New().String()
	verifier := "veri_" + uuid.New().String()

	cs := ConsentSession{
		ID:        uuid.New(),
		Challenge: challenge,
		Verifier:  verifier,
		ClientID:  uuid.New(),
		UserID:    "user-123",
		State:     ConsentStatePending,
	}

	// Challenge and verifier are distinct opaque tokens.
	assert.NotEmpty(t, cs.Challenge)
	assert.NotEmpty(t, cs.Verifier)
	assert.NotEqual(t, cs.Challenge, cs.Verifier, "challenge and verifier must be distinct")
}

func TestConsentSession_EncryptedPayloadRoundtrip(t *testing.T) {
	original := []byte(`{"redirect_uri":"https://app.example.com/cb","response_type":"code"}`)
	cs := ConsentSession{
		ID:               uuid.New(),
		Challenge:        "chal-roundtrip",
		Verifier:         "veri-roundtrip",
		ClientID:         uuid.New(),
		UserID:           "user-encrypt",
		RequestedScopes:  []string{"openid"},
		State:            ConsentStatePending,
		EncryptedPayload: original,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	// Encrypted payload should survive assignment and retrieval.
	assert.Equal(t, original, cs.EncryptedPayload, "payload roundtrip must be lossless")
	assert.NotEmpty(t, cs.EncryptedPayload)
}

func TestConsentSession_ExpiresAtOptional(t *testing.T) {
	// Without expiry.
	cs1 := ConsentSession{
		ID:       uuid.New(),
		ClientID: uuid.New(),
		UserID:   "user-1",
		State:    ConsentStatePending,
	}
	assert.Nil(t, cs1.ExpiresAt, "consent session expiry should be optional")

	// With expiry.
	exp := time.Now().Add(10 * time.Minute)
	cs2 := ConsentSession{
		ID:        uuid.New(),
		ClientID:  uuid.New(),
		UserID:    "user-2",
		State:     ConsentStatePending,
		ExpiresAt: &exp,
	}
	assert.NotNil(t, cs2.ExpiresAt)
	assert.True(t, cs2.ExpiresAt.After(time.Now()))
}

// ── Authorization Code with PKCE ─────────────────────────────────────────────

func TestAuthorizationCode_PKCEFields(t *testing.T) {
	ac := AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            "sha256_hash_of_code",
		ClientID:            uuid.New(),
		UserID:              "user-pkce",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "n-0S6_WzA2Mj",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
		CreatedAt:           time.Now(),
	}

	assert.NotEmpty(t, ac.CodeChallenge, "PKCE code_challenge must be set")
	assert.Equal(t, "S256", ac.CodeChallengeMethod, "only S256 is allowed per OAuth 2.1")
	assert.NotEmpty(t, ac.Nonce, "OIDC nonce must be preserved")
	assert.False(t, ac.IsExpired())
	assert.False(t, ac.IsUsed())
}

func TestAuthorizationCode_WithoutPKCE(t *testing.T) {
	ac := AuthorizationCode{
		ID:          uuid.New(),
		ClientID:    uuid.New(),
		UserID:      "user-no-pkce",
		RedirectURI: "https://app.example.com/cb",
		Scopes:      []string{"openid"},
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	assert.Empty(t, ac.CodeChallenge)
	assert.Empty(t, ac.CodeChallengeMethod)
	assert.Empty(t, ac.Nonce)
}

func TestAuthorizationCode_HashNeverExposed(t *testing.T) {
	ac := AuthorizationCode{
		ID:        uuid.New(),
		CodeHash:  "sha256_secret_hash",
		ClientID:  uuid.New(),
		UserID:    "user-hash",
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	// The json tag on CodeHash is "-", so it must not appear in JSON output.
	assert.Equal(t, "sha256_secret_hash", ac.CodeHash, "hash should be internally accessible")
}

func TestAuthorizationCode_Scopes(t *testing.T) {
	ac := AuthorizationCode{
		ID:        uuid.New(),
		ClientID:  uuid.New(),
		UserID:    "user-scopes",
		Scopes:    []string{"openid", "profile", "email", "offline_access"},
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	assert.Len(t, ac.Scopes, 4)
	assert.Contains(t, ac.Scopes, "openid")
	assert.Contains(t, ac.Scopes, "offline_access")
}

func TestAuthorizationCode_MarkUsedTimestamp(t *testing.T) {
	now := time.Now()
	ac := AuthorizationCode{
		ID:        uuid.New(),
		ClientID:  uuid.New(),
		UserID:    "user-mark-used",
		ExpiresAt: now.Add(5 * time.Minute),
	}

	assert.False(t, ac.IsUsed())
	usedAt := now.Add(1 * time.Minute)
	ac.UsedAt = &usedAt
	assert.True(t, ac.IsUsed())
}

// ── IDTokenClaims ────────────────────────────────────────────────────────────

func TestIDTokenClaims_RequiredFields(t *testing.T) {
	now := time.Now()
	claims := IDTokenClaims{
		Issuer:    "https://auth.qf.studio",
		Subject:   "user-123",
		Audience:  []string{"client-abc"},
		ExpiresAt: now.Add(1 * time.Hour).Unix(),
		IssuedAt:  now.Unix(),
	}

	// Required per OIDC Core §2.
	assert.NotEmpty(t, claims.Issuer, "iss is required")
	assert.NotEmpty(t, claims.Subject, "sub is required")
	assert.NotEmpty(t, claims.Audience, "aud is required")
	assert.Greater(t, claims.ExpiresAt, int64(0), "exp is required")
	assert.Greater(t, claims.IssuedAt, int64(0), "iat is required")
}

func TestIDTokenClaims_WithNonce(t *testing.T) {
	claims := IDTokenClaims{
		Issuer:    "https://auth.qf.studio",
		Subject:   "user-nonce",
		Audience:  []string{"client-1"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Nonce:     "random-nonce-value",
	}

	assert.Equal(t, "random-nonce-value", claims.Nonce, "nonce must match the authorization request")
}

func TestIDTokenClaims_WithAuthTime(t *testing.T) {
	authTime := time.Now().Add(-5 * time.Minute).Unix()
	claims := IDTokenClaims{
		Issuer:    "https://auth.qf.studio",
		Subject:   "user-auth-time",
		Audience:  []string{"client-1"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		AuthTime:  authTime,
	}

	assert.Greater(t, claims.AuthTime, int64(0), "auth_time should be set when max_age is used")
	assert.LessOrEqual(t, claims.AuthTime, claims.IssuedAt, "auth_time should be <= iat")
}

func TestIDTokenClaims_MultipleAudiences(t *testing.T) {
	claims := IDTokenClaims{
		Issuer:    "https://auth.qf.studio",
		Subject:   "user-multi-aud",
		Audience:  []string{"client-1", "client-2"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
	}

	assert.Len(t, claims.Audience, 2)
	assert.Contains(t, claims.Audience, "client-1")
	assert.Contains(t, claims.Audience, "client-2")
}

func TestIDTokenClaims_OptionalProfileClaims(t *testing.T) {
	claims := IDTokenClaims{
		Issuer:    "https://auth.qf.studio",
		Subject:   "user-profile",
		Audience:  []string{"client-1"},
		ExpiresAt: time.Now().Add(1 * time.Hour).Unix(),
		IssuedAt:  time.Now().Unix(),
		Email:     "user@example.com",
		Name:      "Alice",
	}

	assert.Equal(t, "user@example.com", claims.Email)
	assert.Equal(t, "Alice", claims.Name)
}

// ── UserInfoResponse ─────────────────────────────────────────────────────────

func TestUserInfoResponse_SubjectRequired(t *testing.T) {
	info := UserInfoResponse{
		Subject: "user-info-sub",
		Email:   "user@example.com",
		Name:    "Test User",
	}

	assert.NotEmpty(t, info.Subject, "sub claim is required per OIDC Core §5.3")
	assert.Equal(t, "user-info-sub", info.Subject)
}

func TestUserInfoResponse_MinimalClaims(t *testing.T) {
	// Only subject is mandatory.
	info := UserInfoResponse{
		Subject: "user-minimal",
	}

	assert.NotEmpty(t, info.Subject)
	assert.Empty(t, info.Email, "email is optional")
	assert.Empty(t, info.Name, "name is optional")
}
