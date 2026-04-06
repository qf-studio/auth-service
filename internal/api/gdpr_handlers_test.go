package api_test

import (
	"context"
	"encoding/json"
	"fmt"
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

// --- Mock GDPRService ---

type mockGDPRService struct {
	exportUserDataFn func(ctx context.Context, userID string) (*api.GDPRExportData, error)
	deleteAccountFn  func(ctx context.Context, userID string) (*api.GDPRDeletionResponse, error)
	listConsentFn    func(ctx context.Context, userID string) (*api.GDPRConsentList, error)
	grantConsentFn   func(ctx context.Context, userID, consentType string) (*api.GDPRConsentRecord, error)
	revokeConsentFn  func(ctx context.Context, userID, consentType string) error
}

func (m *mockGDPRService) ExportUserData(ctx context.Context, userID string) (*api.GDPRExportData, error) {
	if m.exportUserDataFn != nil {
		return m.exportUserDataFn(ctx, userID)
	}
	return &api.GDPRExportData{
		UserID:     userID,
		Email:      "user@example.com",
		Name:       "Test User",
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Data:       map[string]interface{}{"sessions": []interface{}{}},
		ExportedAt: time.Now().UTC(),
	}, nil
}

func (m *mockGDPRService) DeleteAccount(ctx context.Context, userID string) (*api.GDPRDeletionResponse, error) {
	if m.deleteAccountFn != nil {
		return m.deleteAccountFn(ctx, userID)
	}
	return &api.GDPRDeletionResponse{
		Message:     "account deletion scheduled",
		ScheduledAt: time.Now().UTC(),
	}, nil
}

func (m *mockGDPRService) ListConsent(ctx context.Context, userID string) (*api.GDPRConsentList, error) {
	if m.listConsentFn != nil {
		return m.listConsentFn(ctx, userID)
	}
	return &api.GDPRConsentList{
		Consents: []api.GDPRConsentRecord{
			{Type: "marketing", Granted: true, GrantedAt: time.Now().UTC()},
		},
	}, nil
}

func (m *mockGDPRService) GrantConsent(ctx context.Context, userID, consentType string) (*api.GDPRConsentRecord, error) {
	if m.grantConsentFn != nil {
		return m.grantConsentFn(ctx, userID, consentType)
	}
	return &api.GDPRConsentRecord{
		Type:      consentType,
		Granted:   true,
		GrantedAt: time.Now().UTC(),
	}, nil
}

func (m *mockGDPRService) RevokeConsent(ctx context.Context, userID, consentType string) error {
	if m.revokeConsentFn != nil {
		return m.revokeConsentFn(ctx, userID, consentType)
	}
	return nil
}

// --- Helper ---

func newGDPRRouter(gdprSvc api.GDPRService) *gin.Engine {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		GDPR:  gdprSvc,
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

// --- Export tests ---

func TestGDPRExport_Success(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodGet, "/auth/me/export", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.GDPRExportData
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.UserID)
	assert.Equal(t, "user@example.com", resp.Email)
	assert.NotNil(t, resp.Data)
}

func TestGDPRExport_Unauthorized(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodGet, "/auth/me/export", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGDPRExport_ServiceError(t *testing.T) {
	svc := &mockGDPRService{
		exportUserDataFn: func(_ context.Context, _ string) (*api.GDPRExportData, error) {
			return nil, fmt.Errorf("rate limit exceeded: %w", api.ErrForbidden)
		},
	}
	r := newGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/me/export", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// --- DeleteAccount tests ---

func TestGDPRDeleteAccount_Success(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodDelete, "/auth/me", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusAccepted, w.Code)

	var resp api.GDPRDeletionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "account deletion scheduled", resp.Message)
}

func TestGDPRDeleteAccount_Unauthorized(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodDelete, "/auth/me", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGDPRDeleteAccount_ServiceError(t *testing.T) {
	svc := &mockGDPRService{
		deleteAccountFn: func(_ context.Context, _ string) (*api.GDPRDeletionResponse, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newGDPRRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/me", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- ListConsent tests ---

func TestGDPRListConsent_Success(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodGet, "/auth/me/consent", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.GDPRConsentList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Consents, 1)
	assert.Equal(t, "marketing", resp.Consents[0].Type)
	assert.True(t, resp.Consents[0].Granted)
}

func TestGDPRListConsent_Unauthorized(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodGet, "/auth/me/consent", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGDPRListConsent_ServiceError(t *testing.T) {
	svc := &mockGDPRService{
		listConsentFn: func(_ context.Context, _ string) (*api.GDPRConsentList, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/me/consent", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- GrantConsent tests ---

func TestGDPRGrantConsent_Success(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	body := map[string]string{"type": "analytics"}
	w := doRequest(r, http.MethodPost, "/auth/me/consent", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.GDPRConsentRecord
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "analytics", resp.Type)
	assert.True(t, resp.Granted)
}

func TestGDPRGrantConsent_Unauthorized(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	body := map[string]string{"type": "analytics"}
	w := doRequest(r, http.MethodPost, "/auth/me/consent", body)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGDPRGrantConsent_InvalidBody(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodPost, "/auth/me/consent", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestGDPRGrantConsent_ServiceError(t *testing.T) {
	svc := &mockGDPRService{
		grantConsentFn: func(_ context.Context, _, _ string) (*api.GDPRConsentRecord, error) {
			return nil, fmt.Errorf("consent already exists: %w", api.ErrConflict)
		},
	}
	r := newGDPRRouter(svc)
	body := map[string]string{"type": "marketing"}
	w := doRequest(r, http.MethodPost, "/auth/me/consent", body, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- RevokeConsent tests ---

func TestGDPRRevokeConsent_Success(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodDelete, "/auth/me/consent/marketing", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "consent revoked", resp["message"])
}

func TestGDPRRevokeConsent_Unauthorized(t *testing.T) {
	r := newGDPRRouter(&mockGDPRService{})
	w := doRequest(r, http.MethodDelete, "/auth/me/consent/marketing", nil)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestGDPRRevokeConsent_ServiceError(t *testing.T) {
	svc := &mockGDPRService{
		revokeConsentFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("consent not found: %w", api.ErrNotFound)
		},
	}
	r := newGDPRRouter(svc)
	w := doRequest(r, http.MethodDelete, "/auth/me/consent/marketing", nil, "X-User-ID", "user-42")

	assert.Equal(t, http.StatusNotFound, w.Code)
}
