package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOAuthProvider_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		provider OAuthProvider
		want     bool
	}{
		{"google is valid", OAuthProviderGoogle, true},
		{"github is valid", OAuthProviderGitHub, true},
		{"empty is invalid", OAuthProvider(""), false},
		{"unknown is invalid", OAuthProvider("facebook"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.provider.IsValid())
		})
	}
}

func TestOAuthProvider_String(t *testing.T) {
	assert.Equal(t, "google", OAuthProviderGoogle.String())
	assert.Equal(t, "github", OAuthProviderGitHub.String())
}

func TestOAuthAccount_Fields(t *testing.T) {
	acct := OAuthAccount{
		ID:             "oa_1",
		UserID:         "user_1",
		Provider:       OAuthProviderGoogle,
		ProviderUserID: "goog_123",
		Email:          "user@example.com",
	}
	assert.Equal(t, "oa_1", acct.ID)
	assert.Equal(t, OAuthProviderGoogle, acct.Provider)
	assert.Equal(t, "goog_123", acct.ProviderUserID)
}

func TestOAuthUser_Fields(t *testing.T) {
	u := OAuthUser{
		Provider:       OAuthProviderGitHub,
		ProviderUserID: "gh_456",
		Email:          "dev@example.com",
		Name:           "Dev User",
		AvatarURL:      "https://github.com/avatar.png",
		RawAttributes:  map[string]interface{}{"login": "devuser"},
	}
	assert.Equal(t, OAuthProviderGitHub, u.Provider)
	assert.Equal(t, "gh_456", u.ProviderUserID)
	assert.Equal(t, "Dev User", u.Name)
	assert.Equal(t, "devuser", u.RawAttributes["login"])
}
