package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/qf-studio/auth-service/internal/config"
)

func newTestGoogleProvider(t *testing.T, tokenURL, userInfoURL string) *GoogleProvider {
	t.Helper()
	stateMgr := NewStateManager(testSecret)
	cfg := config.OAuthProviderConfig{
		ClientID:     "google-client-id",
		ClientSecret: "google-client-secret",
		RedirectURI:  "http://localhost/callback",
		Enabled:      true,
	}
	p := NewGoogleProvider(cfg, stateMgr, nil)
	// Override endpoints and userinfo URL for testing.
	p.oauth2Cfg.Endpoint = oauth2.Endpoint{
		AuthURL:   "https://accounts.google.com/o/oauth2/auth",
		TokenURL:  tokenURL,
		AuthStyle: oauth2.AuthStyleInParams,
	}
	return p
}

func TestGoogleProvider_Name(t *testing.T) {
	p := NewGoogleProvider(config.OAuthProviderConfig{}, NewStateManager("s"), nil)
	assert.Equal(t, "google", p.Name())
}

func TestGoogleProvider_GetAuthURL(t *testing.T) {
	stateMgr := NewStateManager(testSecret)
	cfg := config.OAuthProviderConfig{
		ClientID:     "test-client-id",
		ClientSecret: "test-secret",
		RedirectURI:  "http://localhost:4000/auth/oauth/google/callback",
		Enabled:      true,
	}
	p := NewGoogleProvider(cfg, stateMgr, nil)

	authURL, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	q := parsed.Query()
	assert.Equal(t, "test-client-id", q.Get("client_id"))
	assert.NotEmpty(t, q.Get("state"), "should include signed state")
	assert.NotEmpty(t, q.Get("code_challenge"), "should include PKCE challenge")
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Contains(t, q.Get("scope"), "openid")
	assert.Contains(t, q.Get("scope"), "email")

	// The embedded state should be verifiable.
	state := q.Get("state")
	verifier, err := stateMgr.Validate(state)
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
}

func TestGoogleProvider_ExchangeCode(t *testing.T) {
	// Mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"test-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	// Mock userinfo endpoint.
	userInfoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]string{
			"id":    "google-user-123",
			"email": "user@gmail.com",
			"name":  "Test User",
		})
		_, _ = w.Write(resp)
	}))
	defer userInfoServer.Close()

	p := newTestGoogleProvider(t, tokenServer.URL, userInfoServer.URL)
	// Override the httpClient to point userinfo requests to our mock.
	originalClient := p.httpClient
	p.httpClient = &http.Client{
		Transport: &userInfoRewriter{
			targetURL:  userInfoServer.URL,
			underlying: originalClient.Transport,
		},
	}

	ctx := WithCodeVerifier(context.Background(), "test-verifier")
	user, err := p.ExchangeCode(ctx, "auth-code")
	require.NoError(t, err)

	assert.Equal(t, "google-user-123", user.ProviderUserID)
	assert.Equal(t, "user@gmail.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
}

func TestGoogleProvider_ExchangeCode_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := newTestGoogleProvider(t, tokenServer.URL, "")

	ctx := WithCodeVerifier(context.Background(), "verifier")
	_, err := p.ExchangeCode(ctx, "bad-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exchange code")
}

// userInfoRewriter redirects Google userinfo requests to a test server.
type userInfoRewriter struct {
	targetURL  string
	underlying http.RoundTripper
}

func (u *userInfoRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.String() == googleUserInfoURL || req.URL.Host == "www.googleapis.com" {
		newReq := req.Clone(req.Context())
		parsed, _ := url.Parse(u.targetURL)
		newReq.URL = parsed
		newReq.Host = parsed.Host
		transport := u.underlying
		if transport == nil {
			transport = http.DefaultTransport
		}
		return transport.RoundTrip(newReq)
	}
	transport := u.underlying
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}
