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

// ── Mock MFA Service ─────────────────────────────────────────────────────────

type mockMFAService struct {
	initiateEnrollmentFn func(ctx context.Context, userID, email string) (*api.MFAEnrollmentResult, error)
	confirmEnrollmentFn  func(ctx context.Context, userID, code string) ([]string, error)
	verifyTOTPFn         func(ctx context.Context, userID, code string) error
	verifyBackupCodeFn   func(ctx context.Context, userID, code string) error
	completeMFALoginFn   func(ctx context.Context, mfaToken, code, codeType string) (*api.AuthResult, error)
	disableFn            func(ctx context.Context, userID string) error
	getStatusFn          func(ctx context.Context, userID string) (*api.MFAStatusResponse, error)
	isMFAEnabledFn       func(ctx context.Context, userID string) (bool, error)
	generateMFATokenFn   func(ctx context.Context, userID string) (string, error)
}

func (m *mockMFAService) InitiateEnrollment(ctx context.Context, userID, email string) (*api.MFAEnrollmentResult, error) {
	if m.initiateEnrollmentFn != nil {
		return m.initiateEnrollmentFn(ctx, userID, email)
	}
	return &api.MFAEnrollmentResult{Secret: "JBSWY3DPEHPK3PXP", URI: "otpauth://totp/Test:user@test.com?secret=JBSWY3DPEHPK3PXP"}, nil
}

func (m *mockMFAService) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	if m.confirmEnrollmentFn != nil {
		return m.confirmEnrollmentFn(ctx, userID, code)
	}
	return []string{"abcd-1234-efgh-5678", "ijkl-9012-mnop-3456"}, nil
}

func (m *mockMFAService) VerifyTOTP(ctx context.Context, userID, code string) error {
	if m.verifyTOTPFn != nil {
		return m.verifyTOTPFn(ctx, userID, code)
	}
	return nil
}

func (m *mockMFAService) VerifyBackupCode(ctx context.Context, userID, code string) error {
	if m.verifyBackupCodeFn != nil {
		return m.verifyBackupCodeFn(ctx, userID, code)
	}
	return nil
}

func (m *mockMFAService) CompleteMFALogin(ctx context.Context, mfaToken, code, codeType string) (*api.AuthResult, error) {
	if m.completeMFALoginFn != nil {
		return m.completeMFALoginFn(ctx, mfaToken, code, codeType)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_mfa_access",
		RefreshToken: "qf_rt_mfa_refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
		UserID:       "user-1",
	}, nil
}

func (m *mockMFAService) Disable(ctx context.Context, userID string) error {
	if m.disableFn != nil {
		return m.disableFn(ctx, userID)
	}
	return nil
}

func (m *mockMFAService) GetStatus(ctx context.Context, userID string) (*api.MFAStatusResponse, error) {
	if m.getStatusFn != nil {
		return m.getStatusFn(ctx, userID)
	}
	return &api.MFAStatusResponse{Enabled: true, Type: "totp", Confirmed: true, BackupLeft: 10}, nil
}

func (m *mockMFAService) IsMFAEnabled(ctx context.Context, userID string) (bool, error) {
	if m.isMFAEnabledFn != nil {
		return m.isMFAEnabledFn(ctx, userID)
	}
	return true, nil
}

func (m *mockMFAService) GenerateMFAToken(ctx context.Context, userID string) (string, error) {
	if m.generateMFATokenFn != nil {
		return m.generateMFATokenFn(ctx, userID)
	}
	return "mfa-token-123", nil
}

// ── Test helpers ─────────────────────────────────────────────────────────────

func newMFATestRouter(mfaSvc api.MFAService) *gin.Engine {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		MFA:   mfaSvc,
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

// ── MFA Setup Tests ──────────────────────────────────────────────────────────

func TestMFASetup_Success(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/setup", nil, "X-User-ID", "user-1", "X-User-Email", "alice@test.com")
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.MFAEnrollmentResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.NotEmpty(t, resp.Secret)
	assert.Contains(t, resp.URI, "otpauth://totp/")
}

func TestMFASetup_Unauthenticated(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})
	w := doRequest(router, http.MethodPost, "/auth/mfa/setup", nil)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFASetup_AlreadyEnrolled(t *testing.T) {
	mfaSvc := &mockMFAService{
		initiateEnrollmentFn: func(_ context.Context, _, _ string) (*api.MFAEnrollmentResult, error) {
			return nil, api.ErrConflict
		},
	}
	router := newMFATestRouter(mfaSvc)

	w := doRequest(router, http.MethodPost, "/auth/mfa/setup", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ── MFA Confirm Tests ────────────────────────────────────────────────────────

func TestMFAConfirm_Success(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	body := map[string]string{"code": "123456"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.MFAConfirmResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Len(t, resp.BackupCodes, 2)
}

func TestMFAConfirm_InvalidCode(t *testing.T) {
	mfaSvc := &mockMFAService{
		confirmEnrollmentFn: func(_ context.Context, _, _ string) ([]string, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newMFATestRouter(mfaSvc)

	body := map[string]string{"code": "000000"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAConfirm_MissingCode(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/confirm", map[string]string{}, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── MFA Verify Tests (public, no auth) ──────────────────────────────────────

func TestMFAVerify_Success(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	body := map[string]string{
		"mfa_token": "mfa-token-123",
		"code":      "123456",
		"code_type": "totp",
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/verify", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_mfa_access", resp.AccessToken)
	assert.Equal(t, "user-1", resp.UserID)
}

func TestMFAVerify_InvalidToken(t *testing.T) {
	mfaSvc := &mockMFAService{
		completeMFALoginFn: func(_ context.Context, _, _, _ string) (*api.AuthResult, error) {
			return nil, api.ErrUnauthorized
		},
	}
	router := newMFATestRouter(mfaSvc)

	body := map[string]string{
		"mfa_token": "bad-token",
		"code":      "123456",
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/verify", body)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAVerify_BackupCode(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	body := map[string]string{
		"mfa_token": "mfa-token-123",
		"code":      "abcd-1234-efgh-5678",
		"code_type": "backup",
	}
	w := doRequest(router, http.MethodPost, "/auth/mfa/verify", body)
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFAVerify_MissingFields(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	// Missing mfa_token
	body := map[string]string{"code": "123456"}
	w := doRequest(router, http.MethodPost, "/auth/mfa/verify", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)

	// Missing code
	body = map[string]string{"mfa_token": "token"}
	w = doRequest(router, http.MethodPost, "/auth/mfa/verify", body)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── MFA Disable Tests ────────────────────────────────────────────────────────

func TestMFADisable_Success(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	w := doRequest(router, http.MethodPost, "/auth/mfa/disable", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFADisable_NotEnrolled(t *testing.T) {
	mfaSvc := &mockMFAService{
		disableFn: func(_ context.Context, _ string) error {
			return api.ErrNotFound
		},
	}
	router := newMFATestRouter(mfaSvc)

	w := doRequest(router, http.MethodPost, "/auth/mfa/disable", nil, "X-User-ID", "user-1")
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── MFA Status Tests ─────────────────────────────────────────────────────────

func TestMFAStatus_Success(t *testing.T) {
	router := newMFATestRouter(&mockMFAService{})

	w := doRequest(router, http.MethodGet, "/auth/mfa/status", nil, "X-User-ID", "user-1")
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.MFAStatusResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "totp", resp.Type)
	assert.True(t, resp.Confirmed)
	assert.Equal(t, 10, resp.BackupLeft)
}

// ── Login-with-MFA Flow Test ─────────────────────────────────────────────────

func TestLogin_MFAChallenge(t *testing.T) {
	authSvc := &mockAuthService{
		loginFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				MFARequired: true,
				MFAToken:    "mfa-challenge-token",
				UserID:      "user-1",
			}, nil
		},
	}

	svc := &api.Services{
		Auth:  authSvc,
		Token: &mockTokenService{},
		MFA:   &mockMFAService{},
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

	// Step 1: Login returns MFA challenge
	body := map[string]string{
		"email":    "alice@example.com",
		"password": "secure-password-12345",
	}
	w := doRequest(router, http.MethodPost, "/auth/login", body)
	require.Equal(t, http.StatusOK, w.Code)

	var loginResp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &loginResp)
	require.NoError(t, err)
	assert.True(t, loginResp.MFARequired)
	assert.Equal(t, "mfa-challenge-token", loginResp.MFAToken)
	assert.Empty(t, loginResp.AccessToken, "should not return access token during MFA challenge")

	// Step 2: Complete MFA verification
	verifyBody := map[string]string{
		"mfa_token": loginResp.MFAToken,
		"code":      "123456",
		"code_type": "totp",
	}
	w = doRequest(router, http.MethodPost, "/auth/mfa/verify", verifyBody)
	require.Equal(t, http.StatusOK, w.Code)

	var verifyResp api.AuthResult
	err = json.Unmarshal(w.Body.Bytes(), &verifyResp)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_mfa_access", verifyResp.AccessToken)
	assert.False(t, verifyResp.MFARequired)
}
