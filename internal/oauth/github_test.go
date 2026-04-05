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

func newTestGitHubProvider(t *testing.T, tokenURL string) *GitHubProvider {
	t.Helper()
	stateMgr := NewStateManager(testSecret)
	cfg := config.OAuthProviderConfig{
		ClientID:     "github-client-id",
		ClientSecret: "github-client-secret",
		RedirectURI:  "http://localhost/callback",
		Enabled:      true,
	}
	p := NewGitHubProvider(cfg, stateMgr, nil)
	p.oauth2Cfg.Endpoint = oauth2.Endpoint{
		AuthURL:   "https://github.com/login/oauth/authorize",
		TokenURL:  tokenURL,
		AuthStyle: oauth2.AuthStyleInParams,
	}
	return p
}

func TestGitHubProvider_Name(t *testing.T) {
	p := NewGitHubProvider(config.OAuthProviderConfig{}, NewStateManager("s"), nil)
	assert.Equal(t, "github", p.Name())
}

func TestGitHubProvider_GetAuthURL(t *testing.T) {
	stateMgr := NewStateManager(testSecret)
	cfg := config.OAuthProviderConfig{
		ClientID:     "gh-client-id",
		ClientSecret: "gh-secret",
		RedirectURI:  "http://localhost:4000/auth/oauth/github/callback",
		Enabled:      true,
	}
	p := NewGitHubProvider(cfg, stateMgr, nil)

	authURL, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	q := parsed.Query()
	assert.Equal(t, "gh-client-id", q.Get("client_id"))
	assert.NotEmpty(t, q.Get("state"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
	assert.Contains(t, q.Get("scope"), "read:user")
	assert.Contains(t, q.Get("scope"), "user:email")

	// State is verifiable.
	verifier, err := stateMgr.Validate(q.Get("state"))
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
}

func TestGitHubProvider_ExchangeCode(t *testing.T) {
	// Mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gh-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	// Mock GitHub API.
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			resp, _ := json.Marshal(map[string]interface{}{
				"id":    12345,
				"login": "testuser",
				"name":  "Test User",
				"email": "user@example.com",
			})
			_, _ = w.Write(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiServer.Close()

	p := newTestGitHubProvider(t, tokenServer.URL)
	p.httpClient = &http.Client{
		Transport: &githubAPIRewriter{
			apiURL:     apiServer.URL,
			underlying: nil,
		},
	}

	ctx := WithCodeVerifier(context.Background(), "test-verifier")
	user, err := p.ExchangeCode(ctx, "auth-code")
	require.NoError(t, err)

	assert.Equal(t, "12345", user.ProviderUserID)
	assert.Equal(t, "user@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
}

func TestGitHubProvider_ExchangeCode_PrivateEmail(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"gh-token","token_type":"Bearer"}`))
	}))
	defer tokenServer.Close()

	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user":
			// Public email is null — email field omitted.
			resp, _ := json.Marshal(map[string]interface{}{
				"id":    67890,
				"login": "privateuser",
				"name":  "Private User",
			})
			_, _ = w.Write(resp)
		case "/user/emails":
			resp, _ := json.Marshal([]map[string]interface{}{
				{"email": "noreply@users.github.com", "primary": false, "verified": true},
				{"email": "private@example.com", "primary": true, "verified": true},
			})
			_, _ = w.Write(resp)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer apiServer.Close()

	p := newTestGitHubProvider(t, tokenServer.URL)
	p.httpClient = &http.Client{
		Transport: &githubAPIRewriter{apiURL: apiServer.URL},
	}

	ctx := WithCodeVerifier(context.Background(), "verifier")
	user, err := p.ExchangeCode(ctx, "auth-code")
	require.NoError(t, err)

	assert.Equal(t, "67890", user.ProviderUserID)
	assert.Equal(t, "private@example.com", user.Email)
}

func TestGitHubProvider_ExchangeCode_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"bad_verification_code"}`))
	}))
	defer tokenServer.Close()

	p := newTestGitHubProvider(t, tokenServer.URL)
	ctx := WithCodeVerifier(context.Background(), "verifier")
	_, err := p.ExchangeCode(ctx, "bad-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exchange code")
}

// githubAPIRewriter redirects GitHub API calls to a test server.
type githubAPIRewriter struct {
	apiURL     string
	underlying http.RoundTripper
}

func (g *githubAPIRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "api.github.com" {
		parsed, _ := url.Parse(g.apiURL + req.URL.Path)
		newReq := req.Clone(req.Context())
		newReq.URL = parsed
		newReq.Host = parsed.Host
		transport := g.underlying
		if transport == nil {
			transport = http.DefaultTransport
		}
		return transport.RoundTrip(newReq)
	}
	transport := g.underlying
	if transport == nil {
		transport = http.DefaultTransport
	}
	return transport.RoundTrip(req)
}
