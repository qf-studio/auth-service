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

// --- Mock MFAService ---

type mockMFAService struct {
	enrollFn  func(ctx context.Context, userID string) (*api.MFAEnrollResult, error)
	confirmFn func(ctx context.Context, userID, code string) error
	verifyFn  func(ctx context.Context, mfaToken, code string) (*api.AuthResult, error)
}

func (m *mockMFAService) Enroll(ctx context.Context, userID string) (*api.MFAEnrollResult, error) {
	if m.enrollFn != nil {
		return m.enrollFn(ctx, userID)
	}
	return &api.MFAEnrollResult{
		Secret:      "JBSWY3DPEHPK3PXP",
		QRCodeURI:   "otpauth://totp/QuantFlow:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=QuantFlow",
		BackupCodes: []string{"abc123", "def456", "ghi789"},
	}, nil
}

func (m *mockMFAService) Confirm(ctx context.Context, userID, code string) error {
	if m.confirmFn != nil {
		return m.confirmFn(ctx, userID, code)
	}
	return nil
}

func (m *mockMFAService) Verify(ctx context.Context, mfaToken, code string) (*api.AuthResult, error) {
	if m.verifyFn != nil {
		return m.verifyFn(ctx, mfaToken, code)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_mfa_verified",
		RefreshToken: "qf_rt_mfa_verified",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

// --- Helper ---

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
		c.Next()
	}
	mw := &api.MiddlewareStack{Auth: authMW}
	return api.NewPublicRouter(svc, mw, health.NewService())
}

// --- Enroll tests ---

func TestMFAEnroll_Success(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	w := doRequest(r, http.MethodPost, "/auth/mfa/enroll", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.MFAEnrollResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Secret)
	assert.NotEmpty(t, resp.QRCodeURI)
	assert.Len(t, resp.BackupCodes, 3)
}

func TestMFAEnroll_Unauthorized(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	w := doRequest(r, http.MethodPost, "/auth/mfa/enroll", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAEnroll_AlreadyEnrolled(t *testing.T) {
	svc := &mockMFAService{
		enrollFn: func(_ context.Context, _ string) (*api.MFAEnrollResult, error) {
			return nil, fmt.Errorf("already enrolled: %w", api.ErrConflict)
		},
	}
	r := newMFATestRouter(svc)
	w := doRequest(r, http.MethodPost, "/auth/mfa/enroll", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusConflict, w.Code)
}

func TestMFAEnroll_ServiceError(t *testing.T) {
	svc := &mockMFAService{
		enrollFn: func(_ context.Context, _ string) (*api.MFAEnrollResult, error) {
			return nil, fmt.Errorf("internal failure: %w", api.ErrInternalError)
		},
	}
	r := newMFATestRouter(svc)
	w := doRequest(r, http.MethodPost, "/auth/mfa/enroll", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Confirm tests ---

func TestMFAConfirm_Success(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{"code": "123456"}
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "MFA enabled", resp["message"])
}

func TestMFAConfirm_Unauthorized(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{"code": "123456"}
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAConfirm_MissingCode(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{}
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestMFAConfirm_InvalidCodeLength(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{"code": "12345"} // 5 chars, need exactly 6
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestMFAConfirm_ServiceError(t *testing.T) {
	svc := &mockMFAService{
		confirmFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("invalid code: %w", api.ErrUnauthorized)
		},
	}
	r := newMFATestRouter(svc)
	body := map[string]string{"code": "000000"}
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAConfirm_InvalidJSON(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	w := doRequest(r, http.MethodPost, "/auth/mfa/confirm", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Verify tests ---

func TestMFAVerify_Success(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{
		"mfa_token": "mfa-token-123",
		"code":      "123456",
	}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "qf_at_mfa_verified", resp.AccessToken)
	assert.Equal(t, "qf_rt_mfa_verified", resp.RefreshToken)
	assert.Equal(t, "Bearer", resp.TokenType)
}

func TestMFAVerify_WithBackupCode(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{
		"mfa_token": "mfa-token-123",
		"code":      "abc123def456", // 12-char backup code
	}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestMFAVerify_MissingToken(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{"code": "123456"}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestMFAVerify_MissingCode(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	body := map[string]string{"mfa_token": "mfa-token-123"}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestMFAVerify_InvalidCode(t *testing.T) {
	svc := &mockMFAService{
		verifyFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return nil, fmt.Errorf("invalid OTP: %w", api.ErrUnauthorized)
		},
	}
	r := newMFATestRouter(svc)
	body := map[string]string{
		"mfa_token": "mfa-token-123",
		"code":      "000000",
	}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAVerify_ExpiredToken(t *testing.T) {
	svc := &mockMFAService{
		verifyFn: func(_ context.Context, _, _ string) (*api.AuthResult, error) {
			return nil, fmt.Errorf("token expired: %w", api.ErrUnauthorized)
		},
	}
	r := newMFATestRouter(svc)
	body := map[string]string{
		"mfa_token": "expired-token",
		"code":      "123456",
	}
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestMFAVerify_InvalidJSON(t *testing.T) {
	r := newMFATestRouter(&mockMFAService{})
	w := doRequest(r, http.MethodPost, "/auth/mfa/verify", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- MFA routes not registered when service is nil ---

func TestMFARoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		// MFA is nil
	}
	mw := &api.MiddlewareStack{Auth: func(c *gin.Context) {
		c.Set("user_id", "test")
		c.Next()
	}}
	r := api.NewPublicRouter(svc, mw, health.NewService())

	w := doRequest(r, http.MethodPost, "/auth/mfa/enroll", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = doRequest(r, http.MethodPost, "/auth/mfa/confirm", map[string]string{"code": "123456"})
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = doRequest(r, http.MethodPost, "/auth/mfa/verify", map[string]string{"mfa_token": "t", "code": "123456"})
	assert.Equal(t, http.StatusNotFound, w.Code)
}
