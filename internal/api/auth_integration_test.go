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
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockTokenValidator implements middleware.TokenValidator for integration tests.
type mockTokenValidator struct {
	claims      *domain.TokenClaims
	validateErr error
	revoked     bool
	revokeErr   error
}

func (m *mockTokenValidator) ValidateToken(_ context.Context, _ string) (*domain.TokenClaims, error) {
	return m.claims, m.validateErr
}

func (m *mockTokenValidator) IsRevoked(_ context.Context, _ string) (bool, error) {
	return m.revoked, m.revokeErr
}

// newIntegrationRouter builds the full public router with the real AuthMiddleware
// backed by a mock TokenValidator, allowing end-to-end auth-protected route testing.
func newIntegrationRouter(
	authSvc api.AuthService,
	tokenSvc api.TokenService,
	validator middleware.TokenValidator,
) *gin.Engine {
	svc := &api.Services{Auth: authSvc, Token: tokenSvc}
	mw := &api.MiddlewareStack{
		Auth: middleware.AuthMiddleware(validator),
	}
	return api.NewPublicRouter(svc, mw)
}

// TestProtectedRoutes_RequireAuth verifies that all protected endpoints
// return 401 when no Authorization header is provided.
func TestProtectedRoutes_RequireAuth(t *testing.T) {
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject: "user-1",
			TokenID: "tok-1",
		},
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	protectedEndpoints := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodGet, "/auth/me", nil},
		{http.MethodPut, "/auth/me/password", map[string]string{
			"old_password": "old-password-here!!",
			"new_password": "brand-new-secure-password",
		}},
		{http.MethodPost, "/auth/logout", nil},
		{http.MethodPost, "/auth/logout/all", nil},
	}

	for _, ep := range protectedEndpoints {
		t.Run(fmt.Sprintf("%s %s without auth", ep.method, ep.path), func(t *testing.T) {
			w := doRequest(router, ep.method, ep.path, ep.body)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
}

// TestProtectedRoutes_AcceptValidToken verifies that protected endpoints
// accept a valid Bearer token via the real AuthMiddleware.
func TestProtectedRoutes_AcceptValidToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject:    "user-42",
			Roles:      []string{"user"},
			ClientType: domain.ClientTypeUser,
			TokenID:    "tok-abc",
		},
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	t.Run("GET /auth/me returns user info", func(t *testing.T) {
		w := doRequest(router, http.MethodGet, "/auth/me", nil,
			"Authorization", "Bearer qf_at_valid_token")

		require.Equal(t, http.StatusOK, w.Code)
		var resp api.UserInfo
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "user-42", resp.ID)
	})

	t.Run("PUT /auth/me/password succeeds", func(t *testing.T) {
		body := map[string]string{
			"old_password": "old-password-here!!",
			"new_password": "brand-new-secure-password",
		}
		w := doRequest(router, http.MethodPut, "/auth/me/password", body,
			"Authorization", "Bearer qf_at_valid_token")

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST /auth/logout succeeds", func(t *testing.T) {
		w := doRequest(router, http.MethodPost, "/auth/logout", nil,
			"Authorization", "Bearer qf_at_valid_token")

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST /auth/logout/all succeeds", func(t *testing.T) {
		w := doRequest(router, http.MethodPost, "/auth/logout/all", nil,
			"Authorization", "Bearer qf_at_valid_token")

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestProtectedRoutes_RejectInvalidToken verifies that the real AuthMiddleware
// rejects tokens that fail validation.
func TestProtectedRoutes_RejectInvalidToken(t *testing.T) {
	validator := &mockTokenValidator{
		validateErr: fmt.Errorf("signature invalid"),
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	w := doRequest(router, http.MethodGet, "/auth/me", nil,
		"Authorization", "Bearer qf_at_bad_token")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProtectedRoutes_RejectRevokedToken verifies that the real AuthMiddleware
// rejects revoked tokens.
func TestProtectedRoutes_RejectRevokedToken(t *testing.T) {
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject: "user-42",
			TokenID: "tok-revoked",
		},
		revoked: true,
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	w := doRequest(router, http.MethodGet, "/auth/me", nil,
		"Authorization", "Bearer qf_at_revoked_token")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestProtectedRoutes_RejectWrongPrefix verifies that tokens without the
// qf_at_ prefix are rejected by the real AuthMiddleware.
func TestProtectedRoutes_RejectWrongPrefix(t *testing.T) {
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-42", TokenID: "tok-1"},
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	w := doRequest(router, http.MethodGet, "/auth/me", nil,
		"Authorization", "Bearer no_prefix_token")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// TestPublicRoutes_NoAuthRequired verifies that public endpoints remain
// accessible without authentication even when auth middleware is wired.
func TestPublicRoutes_NoAuthRequired(t *testing.T) {
	validator := &mockTokenValidator{
		validateErr: fmt.Errorf("should not be called"),
	}
	router := newIntegrationRouter(&mockAuthService{}, &mockTokenService{}, validator)

	publicEndpoints := []struct {
		method string
		path   string
		body   interface{}
	}{
		{http.MethodGet, "/health", nil},
		{http.MethodGet, "/liveness", nil},
		{http.MethodGet, "/readiness", nil},
		{http.MethodGet, "/.well-known/jwks.json", nil},
		{http.MethodPost, "/auth/register", map[string]string{
			"email":    "alice@example.com",
			"password": "super-secure-password-123",
			"name":     "Alice",
		}},
		{http.MethodPost, "/auth/login", map[string]string{
			"email":    "alice@example.com",
			"password": "super-secure-password-123",
		}},
		{http.MethodPost, "/auth/password/reset", map[string]string{
			"email": "alice@example.com",
		}},
	}

	for _, ep := range publicEndpoints {
		t.Run(fmt.Sprintf("%s %s without auth", ep.method, ep.path), func(t *testing.T) {
			w := doRequest(router, ep.method, ep.path, ep.body)
			// Should NOT be 401 — these are public routes.
			assert.NotEqual(t, http.StatusUnauthorized, w.Code,
				"public endpoint %s %s should not require auth", ep.method, ep.path)
		})
	}
}

// TestIntegrationFlow_LoginUseTokenRefreshLogout exercises the full flow
// using the real AuthMiddleware: login → use access token → refresh → logout.
func TestIntegrationFlow_LoginUseTokenRefreshLogout(t *testing.T) {
	validClaims := &domain.TokenClaims{
		Subject:    "user-flow",
		Roles:      []string{"user"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-flow",
	}

	validator := &mockTokenValidator{claims: validClaims}

	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_flow_access",
				RefreshToken: "qf_rt_flow_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}, nil
		},
		getMeFn: func(_ context.Context, userID string) (*api.UserInfo, error) {
			return &api.UserInfo{ID: userID, Email: "flow@example.com", Name: "Flow User"}, nil
		},
	}

	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_flow_refreshed",
				RefreshToken: "qf_rt_flow_new",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}, nil
		},
	}

	router := newIntegrationRouter(authSvc, tokenSvc, validator)

	// Step 1: Login (public, no auth needed)
	loginBody := map[string]string{
		"email":    "flow@example.com",
		"password": "super-secure-password-123",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", loginBody)
	require.Equal(t, http.StatusOK, w.Code)

	var loginResp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	assert.Equal(t, "qf_at_flow_access", loginResp.AccessToken)

	// Step 2: Use access token to hit protected endpoint
	w = doRequest(router, http.MethodGet, "/auth/me", nil,
		"Authorization", "Bearer "+loginResp.AccessToken)
	require.Equal(t, http.StatusOK, w.Code)

	var meResp api.UserInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &meResp))
	assert.Equal(t, "user-flow", meResp.ID)

	// Step 3: Refresh token (public endpoint)
	refreshBody := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": loginResp.RefreshToken,
	}
	w = doRequest(router, http.MethodPost, "/auth/token", refreshBody)
	require.Equal(t, http.StatusOK, w.Code)

	var refreshResp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshResp))
	assert.Equal(t, "qf_at_flow_refreshed", refreshResp.AccessToken)

	// Step 4: Logout (protected, needs auth)
	w = doRequest(router, http.MethodPost, "/auth/logout", nil,
		"Authorization", "Bearer "+refreshResp.AccessToken)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 5: Verify that without token, protected route rejects
	w = doRequest(router, http.MethodGet, "/auth/me", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
