package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestGoogleProvider_Name(t *testing.T) {
	p := NewGoogleProvider("id", "secret", "https://example.com/callback")
	assert.Equal(t, domain.OAuthProviderGoogle, p.Name())
}

func TestGoogleProvider_AuthCodeURL(t *testing.T) {
	p := NewGoogleProvider("client-id", "secret", "https://example.com/callback")

	url := p.AuthCodeURL("test-state", "test-verifier")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "code_challenge=")
	assert.Contains(t, url, "code_challenge_method=S256")
	assert.Contains(t, url, "client_id=client-id")
}

func TestGoogleProvider_ExchangeCode_UserInfoParsing(t *testing.T) {
	// Mock userinfo endpoint.
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"id":             "google-user-123",
			"email":          "user@gmail.com",
			"name":           "Google User",
			"verified_email": true,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer userInfoServer.Close()

	// Override the userinfo URL for testing.
	origURL := googleUserInfoURL
	googleUserInfoURL = userInfoServer.URL
	defer func() { googleUserInfoURL = origURL }()

	// Mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","expires_in":3600}`))
	}))
	defer tokenServer.Close()

	p := NewGoogleProvider("client-id", "secret", "https://example.com/callback")
	p.cfg.Endpoint.TokenURL = tokenServer.URL
	// Use a plain HTTP client that won't inject OAuth tokens (we handle it via the mock).
	p.httpClient = &http.Client{}

	info, err := p.ExchangeCode(t.Context(), "auth-code", "verifier")
	assert.NoError(t, err)
	assert.Equal(t, "google-user-123", info.ProviderUserID)
	assert.Equal(t, "user@gmail.com", info.Email)
	assert.Equal(t, "Google User", info.Name)
	assert.True(t, info.EmailVerified)
}

func TestGoogleProvider_ExchangeCode_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := NewGoogleProvider("client-id", "secret", "https://example.com/callback")
	p.cfg.Endpoint.TokenURL = tokenServer.URL

	_, err := p.ExchangeCode(t.Context(), "bad-code", "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "google token exchange")
}
