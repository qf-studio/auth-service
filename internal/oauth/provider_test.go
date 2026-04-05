package oauth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/oauth"
)

// ── Google Provider Tests ──────────────────────────────────────────────────

func TestGoogleProvider_Name(t *testing.T) {
	p := oauth.NewGoogleProvider(config.OAuthProviderConfig{}, http.DefaultClient, &mockStateGen{})
	assert.Equal(t, "google", p.Name())
}

func TestGoogleProvider_GetAuthURL(t *testing.T) {
	cfg := config.OAuthProviderConfig{
		ClientID:    "google-client-id",
		RedirectURI: "https://app.example.com/auth/oauth/google/callback",
	}
	p := oauth.NewGoogleProvider(cfg, http.DefaultClient, &mockStateGen{})

	url, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)
	assert.Contains(t, url, "accounts.google.com")
	assert.Contains(t, url, "client_id=google-client-id")
	assert.Contains(t, url, "state=valid-state")
	assert.Contains(t, url, "scope=openid+email+profile")
}

func TestGoogleProvider_ExchangeCode(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"access_token": "google-access-token"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer google-access-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{
			"sub":   "google-user-123",
			"email": "user@gmail.com",
			"name":  "Test User",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer userInfoServer.Close()

	// Use a custom provider that overrides the URLs for testing.
	p := oauth.NewGoogleProviderWithURLs(
		config.OAuthProviderConfig{
			ClientID:     "gid",
			ClientSecret: "gsecret",
			RedirectURI:  "https://app.example.com/callback",
		},
		&http.Client{},
		&mockStateGen{},
		tokenServer.URL,
		userInfoServer.URL,
	)

	user, err := p.ExchangeCode(context.Background(), "auth-code")
	require.NoError(t, err)
	assert.Equal(t, "google-user-123", user.ProviderUserID)
	assert.Equal(t, "user@gmail.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
}

// ── GitHub Provider Tests ──────────────────────────────────────────────────

func TestGitHubProvider_Name(t *testing.T) {
	p := oauth.NewGitHubProvider(config.OAuthProviderConfig{}, http.DefaultClient, &mockStateGen{})
	assert.Equal(t, "github", p.Name())
}

func TestGitHubProvider_GetAuthURL(t *testing.T) {
	cfg := config.OAuthProviderConfig{
		ClientID:    "gh-client-id",
		RedirectURI: "https://app.example.com/auth/oauth/github/callback",
	}
	p := oauth.NewGitHubProvider(cfg, http.DefaultClient, &mockStateGen{})

	url, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)
	assert.Contains(t, url, "github.com/login/oauth/authorize")
	assert.Contains(t, url, "client_id=gh-client-id")
	assert.Contains(t, url, "state=valid-state")
}

func TestGitHubProvider_ExchangeCode(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"access_token": "gh-access-token"}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer gh-access-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"id":    12345,
			"email": "user@github.com",
			"name":  "GH User",
			"login": "ghuser",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer userServer.Close()

	p := oauth.NewGitHubProviderWithURLs(
		config.OAuthProviderConfig{
			ClientID:     "gid",
			ClientSecret: "gsecret",
			RedirectURI:  "https://app.example.com/callback",
		},
		&http.Client{},
		&mockStateGen{},
		tokenServer.URL,
		userServer.URL,
	)

	user, err := p.ExchangeCode(context.Background(), "auth-code")
	require.NoError(t, err)
	assert.Equal(t, "12345", user.ProviderUserID)
	assert.Equal(t, "user@github.com", user.Email)
	assert.Equal(t, "GH User", user.Name)
}

func TestGitHubProvider_ExchangeCode_FallbackToLogin(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "gh-token"}`))
	}))
	defer tokenServer.Close()

	userServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id": 99, "login": "justalogin"}`))
	}))
	defer userServer.Close()

	p := oauth.NewGitHubProviderWithURLs(
		config.OAuthProviderConfig{ClientID: "id", ClientSecret: "s", RedirectURI: "https://x.com/cb"},
		&http.Client{},
		&mockStateGen{},
		tokenServer.URL,
		userServer.URL,
	)

	user, err := p.ExchangeCode(context.Background(), "code")
	require.NoError(t, err)
	assert.Equal(t, "justalogin", user.Name)
}

// ── Apple Provider Tests ───────────────────────────────────────────────────

func TestAppleProvider_Name(t *testing.T) {
	p := oauth.NewAppleProvider(config.OAuthProviderConfig{}, http.DefaultClient, &mockStateGen{})
	assert.Equal(t, "apple", p.Name())
}

func TestAppleProvider_GetAuthURL(t *testing.T) {
	cfg := config.OAuthProviderConfig{
		ClientID:    "apple-client-id",
		RedirectURI: "https://app.example.com/auth/oauth/apple/callback",
	}
	p := oauth.NewAppleProvider(cfg, http.DefaultClient, &mockStateGen{})

	url, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)
	assert.Contains(t, url, "appleid.apple.com/auth/authorize")
	assert.Contains(t, url, "client_id=apple-client-id")
	assert.Contains(t, url, "response_mode=form_post")
}

func TestAppleProvider_ExchangeCode(t *testing.T) {
	// Create a minimal unsigned JWT for testing.
	// Header: {"alg":"none","typ":"JWT"}, Payload: {"sub":"apple-user-123","email":"user@icloud.com"}
	idToken := "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJhcHBsZS11c2VyLTEyMyIsImVtYWlsIjoidXNlckBpY2xvdWQuY29tIn0."

	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]string{"id_token": idToken}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	p := oauth.NewAppleProviderWithURLs(
		config.OAuthProviderConfig{
			ClientID:     "aid",
			ClientSecret: "asecret",
			RedirectURI:  "https://app.example.com/callback",
		},
		&http.Client{},
		&mockStateGen{},
		tokenServer.URL,
	)

	user, err := p.ExchangeCode(context.Background(), "auth-code")
	require.NoError(t, err)
	assert.Equal(t, "apple-user-123", user.ProviderUserID)
	assert.Equal(t, "user@icloud.com", user.Email)
}

func TestAppleProvider_ExchangeCode_MissingIDToken(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token": "at"}`))
	}))
	defer tokenServer.Close()

	p := oauth.NewAppleProviderWithURLs(
		config.OAuthProviderConfig{ClientID: "id", ClientSecret: "s", RedirectURI: "https://x.com/cb"},
		&http.Client{},
		&mockStateGen{},
		tokenServer.URL,
	)

	_, err := p.ExchangeCode(context.Background(), "code")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing id_token")
}
