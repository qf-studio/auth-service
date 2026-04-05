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

// ── OIDC Discovery Document Field Validation (OpenID Connect Discovery 1.0) ──

func TestOIDCDiscovery_RequiredFieldsPerSpec(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)

	// REQUIRED per OpenID Connect Discovery 1.0 §3.
	assert.NotEmpty(t, resp.Issuer, "issuer is REQUIRED")
	assert.NotEmpty(t, resp.AuthorizationEndpoint, "authorization_endpoint is REQUIRED")
	assert.NotEmpty(t, resp.TokenEndpoint, "token_endpoint is REQUIRED")
	assert.NotEmpty(t, resp.JwksURI, "jwks_uri is REQUIRED")
	assert.NotEmpty(t, resp.ResponseTypesSupported, "response_types_supported is REQUIRED")
	assert.NotEmpty(t, resp.SubjectTypesSupported, "subject_types_supported is REQUIRED")
	assert.NotEmpty(t, resp.IDTokenSigningAlgValuesSupported, "id_token_signing_alg_values_supported is REQUIRED")

	// RECOMMENDED per spec.
	assert.NotEmpty(t, resp.UserinfoEndpoint, "userinfo_endpoint is RECOMMENDED")
	assert.NotEmpty(t, resp.ScopesSupported, "scopes_supported is RECOMMENDED")
	assert.NotEmpty(t, resp.GrantTypesSupported, "grant_types_supported is RECOMMENDED")
	assert.NotEmpty(t, resp.TokenEndpointAuthMethodsSupported, "token_endpoint_auth_methods_supported is RECOMMENDED")

	// OAuth 2.1 requires PKCE.
	assert.NotEmpty(t, resp.CodeChallengeMethodsSupported, "code_challenge_methods_supported should be set for OAuth 2.1")
}

func TestOIDCDiscovery_IssuerMatchesBaseURL(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Issuer must be a URL using https scheme (per §3).
	assert.Contains(t, resp.Issuer, "https://", "issuer must use https scheme")

	// All endpoints should be under the issuer's domain.
	assert.Contains(t, resp.AuthorizationEndpoint, "auth.example.com")
	assert.Contains(t, resp.TokenEndpoint, "auth.example.com")
	assert.Contains(t, resp.JwksURI, "auth.example.com")
}

func TestOIDCDiscovery_ScopesIncludeOpenID(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// openid scope is mandatory for OIDC.
	assert.Contains(t, resp.ScopesSupported, "openid", "openid scope is mandatory")
}

func TestOIDCDiscovery_ResponseTypeCodeSupported(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// authorization_code flow requires "code" response type.
	assert.Contains(t, resp.ResponseTypesSupported, "code")
}

func TestOIDCDiscovery_S256CodeChallengeMethod(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// OAuth 2.1 mandates S256 PKCE.
	assert.Contains(t, resp.CodeChallengeMethodsSupported, "S256")
}

func TestOIDCDiscovery_SigningAlgorithm(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	w := doRequest(router, http.MethodGet, "/.well-known/openid-configuration", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCDiscoveryResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Must include ES256 (our primary signing algorithm).
	assert.Contains(t, resp.IDTokenSigningAlgValuesSupported, "ES256")
}

// ── Authorize with PKCE parameters ────────────────────────────────────────────

func TestOIDCAuthorize_WithPKCEParams(t *testing.T) {
	var capturedReq *api.AuthorizeRequest
	svc := &mockOIDCProviderService{
		authorizeFn: func(_ context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
			capturedReq = req
			return &api.AuthorizeResponse{
				RedirectTo: "https://login.example.com/login?challenge=pkce123",
			}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet,
		"/oauth/authorize?client_id=abc&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid+profile&state=xyz&nonce=n123&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256",
		nil)
	require.Equal(t, http.StatusFound, w.Code)

	require.NotNil(t, capturedReq)
	assert.Equal(t, "abc", capturedReq.ClientID)
	assert.Equal(t, "code", capturedReq.ResponseType)
	assert.Equal(t, "xyz", capturedReq.State)
	assert.Equal(t, "n123", capturedReq.Nonce)
	assert.Equal(t, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", capturedReq.CodeChallenge)
	assert.Equal(t, "S256", capturedReq.CodeChallengeMethod)
}

func TestOIDCAuthorize_WithState(t *testing.T) {
	var capturedReq *api.AuthorizeRequest
	svc := &mockOIDCProviderService{
		authorizeFn: func(_ context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
			capturedReq = req
			return &api.AuthorizeResponse{RedirectTo: "https://login.example.com/login?challenge=state123"}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet,
		"/oauth/authorize?client_id=abc&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid&state=csrf-protect",
		nil)
	require.Equal(t, http.StatusFound, w.Code)
	require.NotNil(t, capturedReq)
	assert.Equal(t, "csrf-protect", capturedReq.State)
}

// ── Token Exchange with code_verifier ─────────────────────────────────────────

func TestOIDCToken_WithCodeVerifier(t *testing.T) {
	var capturedReq *api.CodeExchangeRequest
	svc := &mockOIDCProviderService{
		exchangeCodeFn: func(_ context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
			capturedReq = req
			return &api.OIDCTokenResponse{
				AccessToken:  "qf_at_verified",
				TokenType:    "Bearer",
				ExpiresIn:    900,
				IDToken:      "eyJhbGciOiJFUzI1NiJ9.verified.sig",
			}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth_code_pkce",
		"redirect_uri":  "https://app.example.com/cb",
		"client_id":     "client-pkce",
		"code_verifier": "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	require.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedReq)
	assert.Equal(t, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", capturedReq.CodeVerifier)
	assert.Equal(t, "client-pkce", capturedReq.ClientID)
}

func TestOIDCToken_WithClientSecret(t *testing.T) {
	var capturedReq *api.CodeExchangeRequest
	svc := &mockOIDCProviderService{
		exchangeCodeFn: func(_ context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
			capturedReq = req
			return &api.OIDCTokenResponse{
				AccessToken: "qf_at_secret",
				TokenType:   "Bearer",
				ExpiresIn:   900,
			}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	body := map[string]string{
		"grant_type":    "authorization_code",
		"code":          "auth_code_secret",
		"redirect_uri":  "https://app.example.com/cb",
		"client_id":     "client-secret",
		"client_secret": "super-secret",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	require.Equal(t, http.StatusOK, w.Code)

	require.NotNil(t, capturedReq)
	assert.Equal(t, "super-secret", capturedReq.ClientSecret)
}

func TestOIDCToken_ResponseHeaders(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	body := map[string]string{
		"grant_type":   "authorization_code",
		"code":         "auth_code_headers",
		"redirect_uri": "https://app.example.com/cb",
		"client_id":    "client-1",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	require.Equal(t, http.StatusOK, w.Code)

	// RFC 6749 §5.1: Must not be cached.
	assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
	assert.Equal(t, "no-cache", w.Header().Get("Pragma"))
}

func TestOIDCToken_ResponseContainsScope(t *testing.T) {
	router := newOIDCTestRouter(&mockOIDCProviderService{})

	body := map[string]string{
		"grant_type":   "authorization_code",
		"code":         "auth_code_scope",
		"redirect_uri": "https://app.example.com/cb",
		"client_id":    "client-1",
	}
	w := doRequest(router, http.MethodPost, "/oauth/token", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Scope, "scope should be returned in token response")
}

// ── UserInfo claim assembly ──────────────────────────────────────────────────

func TestOIDCUserInfo_ClaimsAssembly(t *testing.T) {
	svc := &mockOIDCProviderService{
		getUserInfoFn: func(_ context.Context, userID string) (*api.OIDCUserInfoResponse, error) {
			return &api.OIDCUserInfoResponse{
				Sub:           userID,
				Email:         "alice@example.com",
				EmailVerified: true,
				Name:          "Alice Wonderland",
			}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet, "/userinfo", nil, "X-User-ID", "user-alice")
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.OIDCUserInfoResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))

	// Sub is REQUIRED per OIDC Core §5.3.
	assert.Equal(t, "user-alice", resp.Sub)
	assert.Equal(t, "alice@example.com", resp.Email)
	assert.True(t, resp.EmailVerified)
	assert.Equal(t, "Alice Wonderland", resp.Name)
}

func TestOIDCUserInfo_MinimalSubOnly(t *testing.T) {
	svc := &mockOIDCProviderService{
		getUserInfoFn: func(_ context.Context, userID string) (*api.OIDCUserInfoResponse, error) {
			return &api.OIDCUserInfoResponse{Sub: userID}, nil
		},
	}
	router := newOIDCTestRouter(svc)

	w := doRequest(router, http.MethodGet, "/userinfo", nil, "X-User-ID", "user-minimal")
	require.Equal(t, http.StatusOK, w.Code)

	var raw map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &raw))
	assert.Equal(t, "user-minimal", raw["sub"])
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
