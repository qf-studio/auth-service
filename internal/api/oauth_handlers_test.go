package api_test

import (
	"context"
	"encoding/json"
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
	getAuthURLFn        func(ctx context.Context, provider string) (*domain.OAuthAuthURL, error)
	handleCallbackFn    func(ctx context.Context, provider, code, state string) (*api.AuthResult, error)
	listLinkedFn        func(ctx context.Context, userID string) (*domain.OAuthLinkedAccounts, error)
	unlinkAccountFn     func(ctx context.Context, userID, provider string) error
}

func (m *mockOAuthService) GetAuthURL(ctx context.Context, provider string) (*domain.OAuthAuthURL, error) {
	if m.getAuthURLFn != nil {
		return m.getAuthURLFn(ctx, provider)
	}
	return &domain.OAuthAuthURL{AuthURL: "https://accounts.google.com/o/oauth2/auth?state=abc"}, nil
}

func (m *mockOAuthService) HandleCallback(ctx context.Context, provider, code, state string) (*api.AuthResult, error) {
	if m.handleCallbackFn != nil {
		return m.handleCallbackFn(ctx, provider, code, state)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_oauth_access",
		RefreshToken: "qf_rt_oauth_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       "user-1",
	}, nil
}

func (m *mockOAuthService) ListLinkedAccounts(ctx context.Context, userID string) (*domain.OAuthLinkedAccounts, error) {
	if m.listLinkedFn != nil {
		return m.listLinkedFn(ctx, userID)
	}
	return &domain.OAuthLinkedAccounts{
		Accounts: []domain.OAuthAccount{
			{ID: "oa-1", UserID: userID, Provider: "google", ProviderUserID: "goog-123", Email: "user@gmail.com"},
		},
	}, nil
}

func (m *mockOAuthService) UnlinkAccount(ctx context.Context, userID, provider string) error {
	if m.unlinkAccountFn != nil {
		return m.unlinkAccountFn(ctx, userID, provider)
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

// ── OAuth Redirect Tests ────────────────────────────────────────────────────

func TestOAuthRedirect_Success(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp domain.OAuthAuthURL
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp.AuthURL, "accounts.google.com")
}

func TestOAuthRedirect_ProviderNotFound(t *testing.T) {
	oauthSvc := &mockOAuthService{
		getAuthURLFn: func(_ context.Context, _ string) (*domain.OAuthAuthURL, error) {
			return nil, api.ErrNotFound
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/unsupported", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── OAuth Callback Tests ────────────────────────────────────────────────────

func TestOAuthCallback_Success(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=auth_code_123&state=abc", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_oauth_access", resp.AccessToken)
	assert.Equal(t, "user-1", resp.UserID)
}

func TestOAuthCallback_MissingCode(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?state=abc", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOAuthCallback_ExchangeFailed(t *testing.T) {
	oauthSvc := &mockOAuthService{
		handleCallbackFn: func(_ context.Context, _, _, _ string) (*api.AuthResult, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodGet, "/auth/oauth/google/callback?code=bad_code&state=abc", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── OAuth List Linked Tests ─────────────────────────────────────────────────

func TestOAuthListLinked_Success(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/me/oauth", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp domain.OAuthLinkedAccounts
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.Accounts, 1)
	assert.Equal(t, "google", resp.Accounts[0].Provider)
}

func TestOAuthListLinked_Unauthenticated(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodGet, "/auth/me/oauth", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── OAuth Unlink Tests ──────────────────────────────────────────────────────

func TestOAuthUnlink_Success(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/google", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestOAuthUnlink_NotFound(t *testing.T) {
	oauthSvc := &mockOAuthService{
		unlinkAccountFn: func(_ context.Context, _, _ string) error {
			return api.ErrNotFound
		},
	}
	router := newOAuthTestRouter(oauthSvc)

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/github", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestOAuthUnlink_Unauthenticated(t *testing.T) {
	router := newOAuthTestRouter(&mockOAuthService{})

	w := doRequest(router, http.MethodDelete, "/auth/me/oauth/google", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── OAuth Routes Not Registered When Service Is Nil ─────────────────────────

func TestOAuthRoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		// OAuth: nil — not set
	}
	router := api.NewPublicRouter(svc, nil, health.NewService())

	w := doRequest(router, http.MethodGet, "/auth/oauth/google", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
