package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// --- Mock services ---

type mockAuthService struct {
	registerFn             func(ctx context.Context, email, password, name string) (*api.UserInfo, error)
	loginFn                func(ctx context.Context, email, password string) (*api.AuthResult, error)
	verifyMFALoginFn       func(ctx context.Context, mfaToken, code string) (*api.AuthResult, error)
	resetPasswordFn        func(ctx context.Context, email string) error
	confirmPasswordResetFn func(ctx context.Context, token, newPassword string) error
	getMeFn                func(ctx context.Context, userID string) (*api.UserInfo, error)
	changePasswordFn       func(ctx context.Context, userID, oldPassword, newPassword string) error
	logoutFn               func(ctx context.Context, userID, token string) error
	logoutAllFn            func(ctx context.Context, userID string) error
}

func (m *mockAuthService) Register(ctx context.Context, email, password, name string) (*api.UserInfo, error) {
	if m.registerFn != nil {
		return m.registerFn(ctx, email, password, name)
	}
	return &api.UserInfo{ID: "user-1", Email: email, Name: name}, nil
}

func (m *mockAuthService) Login(ctx context.Context, email, password string) (*api.AuthResult, error) {
	if m.loginFn != nil {
		return m.loginFn(ctx, email, password)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test_access",
		RefreshToken: "qf_rt_test_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (m *mockAuthService) VerifyMFALogin(ctx context.Context, mfaToken, code string) (*api.AuthResult, error) {
	if m.verifyMFALoginFn != nil {
		return m.verifyMFALoginFn(ctx, mfaToken, code)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test_access",
		RefreshToken: "qf_rt_test_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (m *mockAuthService) ResetPassword(ctx context.Context, email string) error {
	if m.resetPasswordFn != nil {
		return m.resetPasswordFn(ctx, email)
	}
	return nil
}

func (m *mockAuthService) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	if m.confirmPasswordResetFn != nil {
		return m.confirmPasswordResetFn(ctx, token, newPassword)
	}
	return nil
}

func (m *mockAuthService) GetMe(ctx context.Context, userID string) (*api.UserInfo, error) {
	if m.getMeFn != nil {
		return m.getMeFn(ctx, userID)
	}
	return &api.UserInfo{ID: userID, Email: "user@example.com", Name: "Test User"}, nil
}

func (m *mockAuthService) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	if m.changePasswordFn != nil {
		return m.changePasswordFn(ctx, userID, oldPassword, newPassword)
	}
	return nil
}

func (m *mockAuthService) Logout(ctx context.Context, userID, token string) error {
	if m.logoutFn != nil {
		return m.logoutFn(ctx, userID, token)
	}
	return nil
}

func (m *mockAuthService) LogoutAll(ctx context.Context, userID string) error {
	if m.logoutAllFn != nil {
		return m.logoutAllFn(ctx, userID)
	}
	return nil
}

type mockTokenService struct {
	refreshFn           func(ctx context.Context, refreshToken string) (*api.AuthResult, error)
	clientCredentialsFn func(ctx context.Context, clientID, clientSecret string) (*api.AuthResult, error)
	revokeFn            func(ctx context.Context, token string) error
	jwksFn              func(ctx context.Context) (*api.JWKSResponse, error)
}

func (m *mockTokenService) Refresh(ctx context.Context, refreshToken string) (*api.AuthResult, error) {
	if m.refreshFn != nil {
		return m.refreshFn(ctx, refreshToken)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_refreshed",
		RefreshToken: "qf_rt_new_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

func (m *mockTokenService) ClientCredentials(ctx context.Context, clientID, clientSecret string) (*api.AuthResult, error) {
	if m.clientCredentialsFn != nil {
		return m.clientCredentialsFn(ctx, clientID, clientSecret)
	}
	return &api.AuthResult{
		AccessToken: "qf_at_client",
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

func (m *mockTokenService) Revoke(ctx context.Context, token string) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, token)
	}
	return nil
}

func (m *mockTokenService) RefreshWithDPoP(ctx context.Context, refreshToken, jktThumbprint string) (*api.AuthResult, error) {
	return m.Refresh(ctx, refreshToken)
}

func (m *mockTokenService) ClientCredentialsWithDPoP(ctx context.Context, clientID, clientSecret, jktThumbprint string) (*api.AuthResult, error) {
	return m.ClientCredentials(ctx, clientID, clientSecret)
}

func (m *mockTokenService) JWKS(ctx context.Context) (*api.JWKSResponse, error) {
	if m.jwksFn != nil {
		return m.jwksFn(ctx)
	}
	return &api.JWKSResponse{Keys: []interface{}{}}, nil
}

// --- Helpers ---

func newTestRouter(authSvc api.AuthService, tokenSvc api.TokenService) *gin.Engine {
	svc := &api.Services{Auth: authSvc, Token: tokenSvc}
	// Use a simple auth middleware that reads X-User-ID header for testing.
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

func jsonBody(v interface{}) *bytes.Buffer {
	b, _ := json.Marshal(v)
	return bytes.NewBuffer(b)
}

func doRequest(router *gin.Engine, method, path string, body interface{}, headers ...string) *httptest.ResponseRecorder {
	var req *http.Request
	if body != nil {
		req = httptest.NewRequest(method, path, jsonBody(body))
		req.Header.Set("Content-Type", "application/json")
	} else {
		req = httptest.NewRequest(method, path, http.NoBody)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		req.Header.Set(headers[i], headers[i+1])
	}
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// --- Health probe tests ---

func TestHealthEndpoints(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	for _, path := range []string{"/health", "/liveness", "/readiness"} {
		t.Run(path, func(t *testing.T) {
			w := doRequest(router, http.MethodGet, path, nil)
			assert.Equal(t, http.StatusOK, w.Code)
			var resp map[string]interface{}
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
			assert.Equal(t, "healthy", resp["status"])
		})
	}
}

// --- Registration tests ---

func TestRegister_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "super-secure-password-123",
		"name":     "Alice",
	}
	w := doRequest(router, http.MethodPost, "/auth/register", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.UserInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "alice@example.com", resp.Email)
	assert.Equal(t, "Alice", resp.Name)
}

func TestRegister_ValidationError(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	// Missing name, short password
	body := map[string]string{
		"email":    "alice@example.com",
		"password": "short",
	}
	w := doRequest(router, http.MethodPost, "/auth/register", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)

	var resp domain.ErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, domain.CodeValidationError, resp.Code)
}

func TestRegister_InvalidJSON(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	req := httptest.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString("{bad"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestRegister_ServiceError(t *testing.T) {
	authSvc := &mockAuthService{
		registerFn: func(_ context.Context, _, _, _ string) (*api.UserInfo, error) {
			return nil, fmt.Errorf("email already in use: %w", api.ErrConflict)
		},
	}
	router := newTestRouter(authSvc, &mockTokenService{})

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "super-secure-password-123",
		"name":     "Alice",
	}
	w := doRequest(router, http.MethodPost, "/auth/register", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Login tests ---

func TestLogin_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "super-secure-password-123",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Bearer", resp.TokenType)
	assert.NotEmpty(t, resp.AccessToken)
	assert.NotEmpty(t, resp.RefreshToken)
}

func TestLogin_InvalidCredentials(t *testing.T) {
	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return nil, fmt.Errorf("bad credentials: %w", api.ErrUnauthorized)
		},
	}
	router := newTestRouter(authSvc, &mockTokenService{})

	body := map[string]string{
		"email":    "alice@example.com",
		"password": "wrong-password-here!!",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Password reset tests ---

func TestPasswordReset_AlwaysAccepted(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{"email": "anyone@example.com"}
	w := doRequest(router, http.MethodPost, "/auth/password/reset", body)

	// Always 202 to prevent enumeration.
	assert.Equal(t, http.StatusAccepted, w.Code)
}

func TestPasswordResetConfirm_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"token":        "valid-reset-token",
		"new_password": "brand-new-secure-password",
	}
	w := doRequest(router, http.MethodPost, "/auth/password/reset/confirm", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestPasswordResetConfirm_InvalidToken(t *testing.T) {
	authSvc := &mockAuthService{
		confirmPasswordResetFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("invalid reset token: %w", api.ErrUnauthorized)
		},
	}
	router := newTestRouter(authSvc, &mockTokenService{})

	body := map[string]string{
		"token":        "expired-token",
		"new_password": "brand-new-secure-password",
	}
	w := doRequest(router, http.MethodPost, "/auth/password/reset/confirm", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Token endpoint tests ---

func TestToken_RefreshGrant(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "qf_rt_test_refresh",
	}
	w := doRequest(router, http.MethodPost, "/auth/token", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "qf_at_refreshed", resp.AccessToken)
}

func TestToken_ClientCredentialsGrant(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "svc-agent-1",
		"client_secret": "secret-value",
	}
	w := doRequest(router, http.MethodPost, "/auth/token", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "qf_at_client", resp.AccessToken)
}

func TestToken_InvalidGrantType(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"grant_type": "implicit",
	}
	w := doRequest(router, http.MethodPost, "/auth/token", body)

	// Validation rejects unsupported grant_type via oneof tag.
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestToken_RefreshServiceError(t *testing.T) {
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return nil, fmt.Errorf("token expired: %w", api.ErrUnauthorized)
		},
	}
	router := newTestRouter(&mockAuthService{}, tokenSvc)

	body := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": "qf_rt_expired",
	}
	w := doRequest(router, http.MethodPost, "/auth/token", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// --- Revoke tests ---

func TestRevoke_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{"token": "qf_at_some_token"}
	w := doRequest(router, http.MethodPost, "/auth/revoke", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRevoke_MissingToken(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	w := doRequest(router, http.MethodPost, "/auth/revoke", map[string]string{})

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// --- JWKS tests ---

func TestJWKS_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	w := doRequest(router, http.MethodGet, "/.well-known/jwks.json", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.JWKSResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp.Keys)
}

// --- Protected endpoint tests ---

func TestMe_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	w := doRequest(router, http.MethodGet, "/auth/me", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.UserInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.ID)
}

func TestMe_Unauthorized(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	// No X-User-ID header → auth middleware rejects.
	w := doRequest(router, http.MethodGet, "/auth/me", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestChangePassword_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"old_password": "old-password-here!!",
		"new_password": "brand-new-secure-password",
	}
	w := doRequest(router, http.MethodPut, "/auth/me/password", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestChangePassword_Unauthorized(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	body := map[string]string{
		"old_password": "old-password-here!!",
		"new_password": "brand-new-secure-password",
	}
	w := doRequest(router, http.MethodPut, "/auth/me/password", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestLogout_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	w := doRequest(router, http.MethodPost, "/auth/logout", nil,
		"X-User-ID", "user-42",
		"Authorization", "Bearer qf_at_test_token",
	)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestLogoutAll_Success(t *testing.T) {
	router := newTestRouter(&mockAuthService{}, &mockTokenService{})

	w := doRequest(router, http.MethodPost, "/auth/logout/all", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Full auth flow integration test ---

func TestFullAuthFlow_RegisterLoginRefreshLogout(t *testing.T) {
	var capturedRefreshToken string

	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, email, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_flow_access",
				RefreshToken: "qf_rt_flow_refresh",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}, nil
		},
	}
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, rt string) (*api.AuthResult, error) {
			capturedRefreshToken = rt
			return &api.AuthResult{
				AccessToken:  "qf_at_flow_refreshed",
				RefreshToken: "qf_rt_flow_new",
				TokenType:    "Bearer",
				ExpiresIn:    3600,
			}, nil
		},
	}

	router := newTestRouter(authSvc, tokenSvc)

	// Step 1: Register
	regBody := map[string]string{
		"email":    "flow@example.com",
		"password": "super-secure-password-123",
		"name":     "Flow User",
	}
	w := doRequest(router, http.MethodPost, "/auth/register", regBody)
	require.Equal(t, http.StatusCreated, w.Code)

	// Step 2: Login
	loginBody := map[string]string{
		"email":    "flow@example.com",
		"password": "super-secure-password-123",
	}
	w = doRequest(router, http.MethodPost, "/auth/login", loginBody)
	require.Equal(t, http.StatusOK, w.Code)

	var loginResp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &loginResp))
	assert.Equal(t, "qf_at_flow_access", loginResp.AccessToken)
	assert.Equal(t, "qf_rt_flow_refresh", loginResp.RefreshToken)

	// Step 3: Refresh token
	refreshBody := map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": loginResp.RefreshToken,
	}
	w = doRequest(router, http.MethodPost, "/auth/token", refreshBody)
	require.Equal(t, http.StatusOK, w.Code)

	var refreshResp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refreshResp))
	assert.Equal(t, "qf_at_flow_refreshed", refreshResp.AccessToken)
	assert.Equal(t, "qf_rt_flow_refresh", capturedRefreshToken)

	// Step 4: Logout
	w = doRequest(router, http.MethodPost, "/auth/logout", nil,
		"X-User-ID", "user-1",
		"Authorization", "Bearer "+refreshResp.AccessToken,
	)
	require.Equal(t, http.StatusOK, w.Code)
}

// --- Middleware ordering test ---

func TestMiddlewareOrdering(t *testing.T) {
	var order []string

	mw := &api.MiddlewareStack{
		CorrelationID: func(c *gin.Context) {
			order = append(order, "correlation_id")
			c.Next()
		},
		SecurityHeaders: func(c *gin.Context) {
			order = append(order, "security_headers")
			c.Next()
		},
		RateLimit: func(c *gin.Context) {
			order = append(order, "rate_limit")
			c.Next()
		},
		RequestSize: func(c *gin.Context) {
			order = append(order, "request_size")
			c.Next()
		},
		Auth: func(c *gin.Context) {
			c.Set("user_id", "test")
			c.Next()
		},
	}

	svc := &api.Services{Auth: &mockAuthService{}, Token: &mockTokenService{}}
	router := api.NewPublicRouter(svc, mw, health.NewService())

	w := doRequest(router, http.MethodGet, "/health", nil)
	require.Equal(t, http.StatusOK, w.Code)

	expected := []string{"correlation_id", "security_headers", "rate_limit", "request_size"}
	assert.Equal(t, expected, order)
}
