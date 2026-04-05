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

// ── Mock OIDC Provider Service ─────────���───────────────────────────────────

type mockOIDCProviderService struct {
	getDiscoveryFn func(ctx context.Context) (*api.OIDCDiscoveryResponse, error)
	authorizeFn    func(ctx context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error)
	exchangeCodeFn func(ctx context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error)
	getUserInfoFn  func(ctx context.Context, userID string) (*api.OIDCUserInfoResponse, error)
}

func (m *mockOIDCProviderService) GetDiscovery(ctx context.Context) (*api.OIDCDiscoveryResponse, error) {
	if m.getDiscoveryFn != nil {
		return m.getDiscoveryFn(ctx)
	}
	return &api.OIDCDiscoveryResponse{
		Issuer:                "https://auth.example.com",
		AuthorizationEndpoint: "https://auth.example.com/oauth/authorize",
		TokenEndpoint:         "https://auth.example.com/oauth/token",
		UserinfoEndpoint:      "https://auth.example.com/userinfo",
		JwksURI:               "https://auth.example.com/.well-known/jwks.json",
		ScopesSupported:       []string{"openid", "profile", "email"},
		ResponseTypesSupported: []string{"code"},
		GrantTypesSupported:    []string{"authorization_code", "refresh_token"},
		SubjectTypesSupported:  []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"ES256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}, nil
}

func (m *mockOIDCProviderService) Authorize(ctx context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
	if m.authorizeFn != nil {
		return m.authorizeFn(ctx, req)
	}
	return &api.AuthorizeResponse{
		RedirectTo: "https://login.example.com/login?challenge=abc123",
	}, nil
}

func (m *mockOIDCProviderService) ExchangeCode(ctx context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
	if m.exchangeCodeFn != nil {
		return m.exchangeCodeFn(ctx, req)
	}
	return &api.OIDCTokenResponse{
		AccessToken:  "qf_at_oidc_access",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		RefreshToken: "qf_rt_oidc_refresh",
		IDToken:      "eyJhbGciOiJFUzI1NiJ9.test.sig",
		Scope:        "openid profile email",
	}, nil
}

func (m *mockOIDCProviderService) GetUserInfo(ctx context.Context, userID string) (*api.OIDCUserInfoResponse, error) {
	if m.getUserInfoFn != nil {
		return m.getUserInfoFn(ctx, userID)
	}
	return &api.OIDCUserInfoResponse{
		Sub:           userID,
		Email:         "user@example.com",
		EmailVerified: true,
		Name:          "Test User",
	}, nil
}

// ── Test helpers ──────────────────��────────────────────────────────────────

func newOIDCTestRouter(oidcSvc api.OIDCProviderService) *gin.Engine {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		OIDC:  oidcSvc,
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

// ── Discovery Tests ───────────��────────────────────────────────────────────

func TestOIDCDiscovery_Success(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "https://auth.example.com", resp.Issuer)
	assert.Contains(t, resp.ScopesSupported, "openid")
	assert.Equal(t, "https://auth.example.com/.well-known/jwks.json", resp.JwksURI)
}

func TestOIDCDiscovery_ServiceError(t *testing.T) {
	svc := &mockOIDCProviderService{
		getDiscoveryFn: func(_ context.Context) (*api.OIDCDiscoveryResponse, error) {
			return nil, api.ErrInternalError
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ── Authorize Tests ─────────────��──────────────────────────────────────────

func TestOIDCAuthorize_Success(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet,
		"/oauth/authorize?client_id=abc&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid",
		nil)
	require.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "login.example.com")
}

func TestOIDCAuthorize_MissingParams(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/oauth/authorize?client_id=abc", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCAuthorize_ServiceError(t *testing.T) {
	svc := &mockOIDCProviderService{
		authorizeFn: func(_ context.Context, _ *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
			return nil, api.ErrNotFound
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet,
		"/oauth/authorize?client_id=abc&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid",
		nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Token Exchange Tests ───────────────────────────────────────────────────

func TestOIDCToken_Success(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	body := map[string]string{
		"grant_type":   "authorization_code",
		"code":         "auth_code_xyz",
		"redirect_uri": "https://app.example.com/cb",
		"client_id":    "client-1",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCTokenResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_oidc_access", resp.AccessToken)
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.NotEmpty(t, resp.IDToken)
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
}

func TestOIDCToken_UnsupportedGrantType(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	body := map[string]string{
		"grant_type":   "client_credentials",
		"code":         "auth_code_xyz",
		"redirect_uri": "https://app.example.com/cb",
		"client_id":    "client-1",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCToken_MissingFields(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	body := map[string]string{
		"grant_type": "authorization_code",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestOIDCToken_ExchangeError(t *testing.T) {
	svc := &mockOIDCProviderService{
		exchangeCodeFn: func(_ context.Context, _ *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newOIDCTestRouter(svc)

	body := map[string]string{
		"grant_type":   "authorization_code",
		"code":         "bad_code",
		"redirect_uri": "https://app.example.com/cb",
		"client_id":    "client-1",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── UserInfo Tests ──────��─────────────────────���────────────────────��───────

func TestOIDCUserInfo_Success(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/userinfo", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCUserInfoResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user-1", resp.Sub)
	assert.Equal(t, "user@example.com", resp.Email)
	assert.True(t, resp.EmailVerified)
}

func TestOIDCUserInfo_Unauthenticated(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/userinfo", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestOIDCUserInfo_ServiceError(t *testing.T) {
	svc := &mockOIDCProviderService{
		getUserInfoFn: func(_ context.Context, _ string) (*api.OIDCUserInfoResponse, error) {
			return nil, api.ErrNotFound
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet, "/userinfo", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Routes not registered when OIDC is nil ─────────────────────────────────

func TestOIDCRoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		// OIDC: nil
	}
	router := api.NewPublicRouter(svc, nil, health.NewService())

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/.well-known/openid-configuration"},
		{http.MethodGet, "/oauth/authorize?client_id=abc&redirect_uri=x&response_type=code&scope=openid"},
		{http.MethodPost, "/oauth/token"},
		{http.MethodGet, "/userinfo"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := doRequest(router, tc.method, tc.path, nil)
			assert.Equal(t, http.StatusNotFound, w.Code)
		})
	}
}
