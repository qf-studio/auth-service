package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

// ── Mock OAuth Service ──────────────────────────────────────────────────────

type mockOAuthService struct {
	getAuthURLFn          func(ctx context.Context, provider, state, codeVerifier string) (string, error)
	handleCallbackFn      func(ctx context.Context, provider, code, state string) (*api.OAuthCallbackResult, error)
	listLinkedProvidersFn func(ctx context.Context, userID string) ([]api.LinkedProvider, error)
	unlinkProviderFn      func(ctx context.Context, userID, provider string) error
}

func (m *mockOAuthService) GetAuthURL(ctx context.Context, provider, state, codeVerifier string) (string, error) {
	if m.getAuthURLFn != nil {
		return m.getAuthURLFn(ctx, provider, state, codeVerifier)
	}
	return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state, nil
}

func (m *mockOAuthService) HandleCallback(ctx context.Context, provider, code, state string) (*api.OAuthCallbackResult, error) {
	if m.handleCallbackFn != nil {
		return m.handleCallbackFn(ctx, provider, code, state)
	}
	return &api.OAuthCallbackResult{
		AccessToken:  "qf_at_oauth_access",
		RefreshToken: "qf_rt_oauth_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       "user-oauth-1",
	}, nil
}

func (m *mockOAuthService) ListLinkedProviders(ctx context.Context, userID string) ([]api.LinkedProvider, error) {
	if m.listLinkedProvidersFn != nil {
		return m.listLinkedProvidersFn(ctx, userID)
	}
	return []api.LinkedProvider{
		{Provider: "google", Email: "user@gmail.com", LinkedAt: "2026-01-15T10:00:00Z"},
	}, nil
}

func (m *mockOAuthService) UnlinkProvider(ctx context.Context, userID, provider string) error {
	if m.unlinkProviderFn != nil {
		return m.unlinkProviderFn(ctx, userID, provider)
	}
	return nil
}

// ── Test helpers ────────────────────────────────────────────────────────────

func newOAuthTestRouter(oauthSvc api.OAuthService) *gin.Engine {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		OAuth: oauthSvc,
	}
	authMW := func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing authentication")
			return
		}
		c.Set("user_id", userID)
		c.Next()
	}
	mw := &api.MiddlewareStack{Auth: authMW}
	return api.NewPublicRouter(svc, mw, health.NewService())
}

// ── Initiate Tests ──────────────────────────────────────────────────────────

func TestOAuthInitiate_Redirect(t *testing.T) {
	var capturedProvider, capturedState, capturedVerifier string
	oauthSvc := &mockOAuthService{
		getAuthURLFn: func(_ context.Context, provider, state, codeVerifier string) (string, error) {
			capturedProvider = provider
			capturedState = state
			capturedVerifier = codeVerifier
			return "https://accounts.google.com/o/oauth2/v2/auth?state=" + state, nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google", nil)
	require.Equal(t, http.StatusFound, w.Code)

	location := w.Header().Get("Location")
	assert.Contains(t, location, "https://accounts.google.com/o/oauth2/v2/auth")
	assert.Equal(t, "google", capturedProvider)
	assert.NotEmpty(t, capturedState, "state token should be generated")
	assert.NotEmpty(t, capturedVerifier, "code verifier should be generated")
}

func TestOAuthInitiate_ProviderNotFound(t *testing.T) {
	oauthSvc := &mockOAuthService{
		getAuthURLFn: func(_ context.Context, provider, _, _ string) (string, error) {
			return "", fmt.Errorf("provider %q not found: %w", provider, api.ErrNotFound)
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/invalid", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestOAuthInitiate_ServiceError(t *testing.T) {
	oauthSvc := &mockOAuthService{
		getAuthURLFn: func(_ context.Context, _, _, _ string) (string, error) {
			return "", fmt.Errorf("config error: %w", api.ErrInternalError)
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Callback Tests ──────────────────────────────────────────────────────────

func TestOAuthCallback_Success(t *testing.T) {
	var capturedProvider, capturedCode, capturedState string
	oauthSvc := &mockOAuthService{
		handleCallbackFn: func(_ context.Context, provider, code, state string) (*api.OAuthCallbackResult, error) {
			capturedProvider = provider
			capturedCode = code
			capturedState = state
			return &api.OAuthCallbackResult{
				AccessToken:  "qf_at_oauth_access",
				RefreshToken: "qf_rt_oauth_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				UserID:       "user-oauth-1",
			}, nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=auth-code-123&state=csrf-state-456", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OAuthCallbackResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_oauth_access", resp.AccessToken)
	assert.Equal(t, "qf_rt_oauth_refresh", resp.RefreshToken)
	assert.Equal(t, "user-oauth-1", resp.UserID)
	assert.Equal(t, "google", capturedProvider)
	assert.Equal(t, "auth-code-123", capturedCode)
	assert.Equal(t, "csrf-state-456", capturedState)
}

func TestOAuthCallback_AccountLinking(t *testing.T) {
	oauthSvc := &mockOAuthService{
		handleCallbackFn: func(_ context.Context, _, _, _ string) (*api.OAuthCallbackResult, error) {
			return &api.OAuthCallbackResult{
				AccessToken:  "qf_at_linked",
				RefreshToken: "qf_rt_linked",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				UserID:       "existing-user-1",
				NewAccount:   false,
			}, nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/github/callback?code=gh-code&state=state-1", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OAuthCallbackResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "existing-user-1", resp.UserID)
	assert.False(t, resp.NewAccount)
}

func TestOAuthCallback_MFAChallenge(t *testing.T) {
	oauthSvc := &mockOAuthService{
		handleCallbackFn: func(_ context.Context, _, _, _ string) (*api.OAuthCallbackResult, error) {
			return &api.OAuthCallbackResult{
				MFARequired: true,
				MFAToken:    "mfa-oauth-token",
				UserID:      "mfa-user-1",
			}, nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=code&state=state", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OAuthCallbackResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.MFARequired)
	assert.Equal(t, "mfa-oauth-token", resp.MFAToken)
	assert.Empty(t, resp.AccessToken)
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?state=state-1", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_MissingState(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=code-1", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_ProviderError(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?error=access_denied&state=s&code=c", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp domain.ErrorResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.Error, "access_denied")
}

func TestOAuthCallback_InvalidState(t *testing.T) {
	oauthSvc := &mockOAuthService{
		handleCallbackFn: func(_ context.Context, _, _, _ string) (*api.OAuthCallbackResult, error) {
			return nil, fmt.Errorf("invalid state: %w", api.ErrUnauthorized)
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=code&state=bad-state", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── List Linked Providers Tests ─────────────────────────────────────────────

func TestOAuthListProviders_Success(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/me/oauth", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []api.LinkedProvider `json:"providers"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Providers, 1)
	assert.Equal(t, "google", resp.Providers[0].Provider)
	assert.Equal(t, "user@gmail.com", resp.Providers[0].Email)
}

func TestOAuthListProviders_Empty(t *testing.T) {
	oauthSvc := &mockOAuthService{
		listLinkedProvidersFn: func(_ context.Context, _ string) ([]api.LinkedProvider, error) {
			return []api.LinkedProvider{}, nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/me/oauth", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Providers []api.LinkedProvider `json:"providers"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Empty(t, resp.Providers)
}

func TestOAuthListProviders_Unauthenticated(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/me/oauth", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Unlink Provider Tests ───────────────────────────────────────────────────

func TestOAuthUnlink_Success(t *testing.T) {
	var capturedUserID, capturedProvider string
	oauthSvc := &mockOAuthService{
		unlinkProviderFn: func(_ context.Context, userID, provider string) error {
			capturedUserID = userID
			capturedProvider = provider
			return nil
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/google", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "user-1", capturedUserID)
	assert.Equal(t, "google", capturedProvider)
}

func TestOAuthUnlink_ProviderNotFound(t *testing.T) {
	oauthSvc := &mockOAuthService{
		unlinkProviderFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("not linked: %w", api.ErrNotFound)
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/unknown", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestOAuthUnlink_Unauthenticated(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/google", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── OAuth Disabled (nil service) ────────────────────────────────────────────

func TestOAuth_DisabledReturns404(t *testing.T) {
	// When OAuth is nil, routes should not be registered → 404.
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		// OAuth: nil
	}
	router := api.NewPublicRouter(svc, nil, health.NewService())

	for _, path := range []string{
		"/auth/oauth/google",
		"/auth/oauth/google/callback?code=c&state=s",
		"/auth/me/oauth",
	} {
		w := doRequest(router, http.MethodGet, path, nil)
		assert.Equal(t, http.StatusNotFound, w.Code, "path %s should 404 when OAuth disabled", path)
	}
}
