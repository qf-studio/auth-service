package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

// ── Mock WebAuthn Service ───────────────────────────────────────────────────

type mockWebAuthnService struct {
	beginRegistrationFn  func(ctx context.Context, userID, email string) (interface{}, error)
	finishRegistrationFn func(ctx context.Context, userID, email string, body []byte) error
	beginLoginFn         func(ctx context.Context, mfaToken string) (interface{}, error)
	finishLoginFn        func(ctx context.Context, mfaToken string, body []byte) (*api.AuthResult, error)
	listCredentialsFn    func(ctx context.Context, userID string) ([]api.WebAuthnCredentialInfo, error)
	deleteCredentialFn   func(ctx context.Context, userID, credentialID string) error
}

func (m *mockWebAuthnService) BeginRegistration(ctx context.Context, userID, email string) (interface{}, error) {
	if m.beginRegistrationFn != nil {
		return m.beginRegistrationFn(ctx, userID, email)
	}
	return map[string]interface{}{"publicKey": map[string]interface{}{"challenge": "dGVzdC1jaGFsbGVuZ2U"}}, nil
}

func (m *mockWebAuthnService) FinishRegistration(ctx context.Context, userID, email string, body []byte) error {
	if m.finishRegistrationFn != nil {
		return m.finishRegistrationFn(ctx, userID, email, body)
	}
	return nil
}

func (m *mockWebAuthnService) BeginLogin(ctx context.Context, mfaToken string) (interface{}, error) {
	if m.beginLoginFn != nil {
		return m.beginLoginFn(ctx, mfaToken)
	}
	return map[string]interface{}{"publicKey": map[string]interface{}{"challenge": "bG9naW4tY2hhbGxlbmdl"}}, nil
}

func (m *mockWebAuthnService) FinishLogin(ctx context.Context, mfaToken string, body []byte) (*api.AuthResult, error) {
	if m.finishLoginFn != nil {
		return m.finishLoginFn(ctx, mfaToken, body)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_webauthn_access",
		RefreshToken: "qf_rt_webauthn_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       "user-1",
	}, nil
}

func (m *mockWebAuthnService) ListCredentials(ctx context.Context, userID string) ([]api.WebAuthnCredentialInfo, error) {
	if m.listCredentialsFn != nil {
		return m.listCredentialsFn(ctx, userID)
	}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	return []api.WebAuthnCredentialInfo{
		{ID: "cred-1", Name: "YubiKey", CreatedAt: now, LastUsedAt: &now},
	}, nil
}

func (m *mockWebAuthnService) DeleteCredential(ctx context.Context, userID, credentialID string) error {
	if m.deleteCredentialFn != nil {
		return m.deleteCredentialFn(ctx, userID, credentialID)
	}
	return nil
}

// ── Test helpers ────────────────────────────────────────────────────────────

func newWebAuthnTestRouter(webauthnSvc api.WebAuthnService) *gin.Engine {
	svc := &api.Services{
		Auth:     &mockAuthService{},
		Token:    &mockTokenService{},
		WebAuthn: webauthnSvc,
	}
	authMW := func(c *gin.Context) {
		userID := c.GetHeader("X-User-ID")
		if userID == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing authentication")
			return
		}
		c.Set("user_id", userID)
		c.Set("user_email", c.GetHeader("X-User-Email"))
		c.Next()
	}
	mw := &api.MiddlewareStack{Auth: authMW}
	return api.NewPublicRouter(svc, mw, health.NewService())
}

// ── Registration Begin Tests ────────────────────────────────────────────────

func TestWebAuthnBeginRegistration_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/begin", nil,
		"X-User-ID", "user-1", "X-User-Email", "alice@test.com")
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "publicKey")
}

func TestWebAuthnBeginRegistration_Unauthenticated(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/begin", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWebAuthnBeginRegistration_ServiceError(t *testing.T) {
	svc := &mockWebAuthnService{
		beginRegistrationFn: func(_ context.Context, _, _ string) (interface{}, error) {
			return nil, api.ErrConflict
		},
	}
	router := newWebAuthnTestRouter(svc)

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/begin", nil,
		"X-User-ID", "user-1", "X-User-Email", "alice@test.com")
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── Registration Finish Tests ───────────────────────────────────────────────

func TestWebAuthnFinishRegistration_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	body := map[string]interface{}{
		"id":       "dGVzdC1jcmVk",
		"type":     "public-key",
		"response": map[string]string{"clientDataJSON": "e30", "attestationObject": "oA"},
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/finish", body,
		"X-User-ID", "user-1", "X-User-Email", "alice@test.com")
	require.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "WebAuthn credential registered", resp["message"])
}

func TestWebAuthnFinishRegistration_Unauthenticated(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	body := map[string]string{"id": "test"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/finish", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWebAuthnFinishRegistration_EmptyBody(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/finish", nil,
		"X-User-ID", "user-1")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebAuthnFinishRegistration_ServiceError(t *testing.T) {
	svc := &mockWebAuthnService{
		finishRegistrationFn: func(_ context.Context, _, _ string, _ []byte) error {
			return api.ErrUnauthorized
		},
	}
	router := newWebAuthnTestRouter(svc)

	body := map[string]string{"id": "test"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/register/finish", body,
		"X-User-ID", "user-1")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Login Begin Tests ───────────────────────────────────────────────────────

func TestWebAuthnBeginLogin_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	body := map[string]string{"mfa_token": "mfa-tok-123"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/begin", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Contains(t, resp, "publicKey")
}

func TestWebAuthnBeginLogin_MissingMFAToken(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/begin", map[string]string{})
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebAuthnBeginLogin_InvalidMFAToken(t *testing.T) {
	svc := &mockWebAuthnService{
		beginLoginFn: func(_ context.Context, _ string) (interface{}, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newWebAuthnTestRouter(svc)

	body := map[string]string{"mfa_token": "bad-token"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/begin", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWebAuthnBeginLogin_NoCredentials(t *testing.T) {
	svc := &mockWebAuthnService{
		beginLoginFn: func(_ context.Context, _ string) (interface{}, error) {
			return nil, api.ErrNotFound
		},
	}
	router := newWebAuthnTestRouter(svc)

	body := map[string]string{"mfa_token": "mfa-tok-123"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/begin", body)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Login Verify Tests ──────────────────────────────────────────────────────

func TestWebAuthnVerifyLogin_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	body := map[string]interface{}{
		"mfa_token": "mfa-tok-123",
		"id":        "dGVzdC1jcmVk",
		"type":      "public-key",
		"response": map[string]string{
			"clientDataJSON":    "e30",
			"authenticatorData": "AA",
			"signature":         "MEUCIQC",
		},
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/verify", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_webauthn_access", resp.AccessToken)
	assert.Equal(t, "user-1", resp.UserID)
}

func TestWebAuthnVerifyLogin_EmptyBody(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/verify", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebAuthnVerifyLogin_MissingMFAToken(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	body := map[string]string{"id": "test"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/verify", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWebAuthnVerifyLogin_InvalidAssertion(t *testing.T) {
	svc := &mockWebAuthnService{
		finishLoginFn: func(_ context.Context, _ string, _ []byte) (*api.AuthResult, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newWebAuthnTestRouter(svc)

	body := map[string]interface{}{
		"mfa_token": "mfa-tok-123",
		"id":        "bad",
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/verify", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Credential List Tests ───────────────────────────────────────────────────

func TestWebAuthnListCredentials_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodGet, "/auth/mfa/webauthn/credentials", nil,
		"X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Credentials []api.WebAuthnCredentialInfo `json:"credentials"`
	}
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	require.Len(t, resp.Credentials, 1)
	assert.Equal(t, "cred-1", resp.Credentials[0].ID)
	assert.Equal(t, "YubiKey", resp.Credentials[0].Name)
}

func TestWebAuthnListCredentials_Unauthenticated(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodGet, "/auth/mfa/webauthn/credentials", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ── Credential Delete Tests ─────────────────────────────────────────────────

func TestWebAuthnDeleteCredential_Success(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodDelete, "/auth/mfa/webauthn/credentials/cred-1", nil,
		"X-User-ID", "user-1")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestWebAuthnDeleteCredential_Unauthenticated(t *testing.T) {
	router := newWebAuthnTestRouter(&mockWebAuthnService{})

	w := doRequest(router, http.MethodDelete, "/auth/mfa/webauthn/credentials/cred-1", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestWebAuthnDeleteCredential_NotFound(t *testing.T) {
	svc := &mockWebAuthnService{
		deleteCredentialFn: func(_ context.Context, _, _ string) error {
			return api.ErrNotFound
		},
	}
	router := newWebAuthnTestRouter(svc)

	w := doRequest(router, http.MethodDelete, "/auth/mfa/webauthn/credentials/bad-id", nil,
		"X-User-ID", "user-1")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── WebAuthn MFA Login Flow Test ────────────────────────────────────────────

func TestWebAuthn_MFALoginFlow(t *testing.T) {
	// Step 1: Login returns MFA challenge
	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				MFARequired: true,
				MFAToken:    "mfa-challenge-webauthn",
				UserID:      "user-1",
			}, nil
		},
	}

	webauthnSvc := &mockWebAuthnService{}

	svc := &api.Services{
		Auth:     authSvc,
		Token:    &mockTokenService{},
		MFA:      &mockMFAService{},
		WebAuthn: webauthnSvc,
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
	router := api.NewPublicRouter(svc, mw, health.NewService())

	// Step 1: Login → MFA required
	loginBody := map[string]string{
		"email":    "alice@example.com",
		"password": "secure-password-12345",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", loginBody)
	require.Equal(t, http.StatusOK, w.Code)

	var loginResp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.True(t, loginResp.MFARequired)
	assert.Equal(t, "mfa-challenge-webauthn", loginResp.MFAToken)

	// Step 2: Begin WebAuthn login
	beginBody := map[string]string{"mfa_token": loginResp.MFAToken}
	w = doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/begin", beginBody)
	require.Equal(t, http.StatusOK, w.Code)

	// Step 3: Verify WebAuthn assertion → tokens issued
	verifyBody := map[string]interface{}{
		"mfa_token": loginResp.MFAToken,
		"id":        "dGVzdC1jcmVk",
		"type":      "public-key",
		"response":  map[string]string{"clientDataJSON": "e30", "authenticatorData": "AA", "signature": "sig"},
	}
	w = doRequest(router, http.MethodPost, "/auth/mfa/webauthn/login/verify", verifyBody)
	require.Equal(t, http.StatusOK, w.Code)

	var verifyResp api.AuthResult
	err = json.Unmarshal(w.Body.Bytes(), &verifyResp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_webauthn_access", verifyResp.AccessToken)
	assert.False(t, verifyResp.MFARequired)
}
