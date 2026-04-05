package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestGitHubProvider_Name(t *testing.T) {
	p := NewGitHubProvider("id", "secret", "https://example.com/callback")
	assert.Equal(t, domain.OAuthProviderGitHub, p.Name())
}

func TestGitHubProvider_AuthCodeURL(t *testing.T) {
	p := NewGitHubProvider("client-id", "secret", "https://example.com/callback")
	url := p.AuthCodeURL("test-state", "test-verifier")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "client_id=client-id")
}

func TestGitHubProvider_ExchangeCode_WithProfileEmail(t *testing.T) {
	// Mock user endpoint.
	userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"id":    42,
				"name":  "GitHub User",
				"login": "ghuser",
				"email": "ghuser@example.com",
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/user/emails" {
			w.Header().Set("Content-Type", "application/json")
			emails := []map[string]interface{}{
				{"email": "ghuser@example.com", "primary": true, "verified": true},
			}
			_ = json.NewEncoder(w).Encode(emails)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer userServer.Close()

	// Override GitHub API URLs.
	origUserURL := githubUserURL
	origEmailsURL := githubEmailsURL
	githubUserURL = userServer.URL + "/user"
	githubEmailsURL = userServer.URL + "/user/emails"
	defer func() {
		githubUserURL = origUserURL
		githubEmailsURL = origEmailsURL
	}()

	// Mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer","scope":"user:email"}`))
	}))
	defer tokenServer.Close()

	p := NewGitHubProvider("client-id", "secret", "https://example.com/callback")
	p.cfg.Endpoint.TokenURL = tokenServer.URL
	p.httpClient = &http.Client{}

	info, err := p.ExchangeCode(t.Context(), "auth-code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "42", info.ProviderUserID)
	assert.Equal(t, "ghuser@example.com", info.Email)
	assert.Equal(t, "GitHub User", info.Name)
	assert.True(t, info.EmailVerified)
}

func TestGitHubProvider_ExchangeCode_FallbackToEmailsEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user" {
			w.Header().Set("Content-Type", "application/json")
			resp := map[string]interface{}{
				"id":    99,
				"name":  "",
				"login": "noemail",
				"email": nil,
			}
			_ = json.NewEncoder(w).Encode(resp)
			return
		}
		if r.URL.Path == "/user/emails" {
			w.Header().Set("Content-Type", "application/json")
			emails := []map[string]interface{}{
				{"email": "secondary@example.com", "primary": false, "verified": true},
				{"email": "primary@example.com", "primary": true, "verified": true},
			}
			_ = json.NewEncoder(w).Encode(emails)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	origUserURL := githubUserURL
	origEmailsURL := githubEmailsURL
	githubUserURL = server.URL + "/user"
	githubEmailsURL = server.URL + "/user/emails"
	defer func() {
		githubUserURL = origUserURL
		githubEmailsURL = origEmailsURL
	}()

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	p := NewGitHubProvider("client-id", "secret", "https://example.com/callback")
	p.cfg.Endpoint.TokenURL = tokenServer.URL
	p.httpClient = &http.Client{}

	info, err := p.ExchangeCode(t.Context(), "auth-code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "99", info.ProviderUserID)
	assert.Equal(t, "primary@example.com", info.Email)
	assert.Equal(t, "noemail", info.Name) // Falls back to login
	assert.True(t, info.EmailVerified)
}

func TestGitHubProvider_ExchangeCode_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
	}))
	defer tokenServer.Close()

	p := NewGitHubProvider("client-id", "secret", "https://example.com/callback")
	p.cfg.Endpoint.TokenURL = tokenServer.URL

	_, err := p.ExchangeCode(t.Context(), "bad-code", "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "github token exchange")
}
