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
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminGDPRService ---

type mockAdminGDPRService struct {
	exportUserDataFn func(ctx context.Context, userID string) (*api.AdminGDPRExportData, error)
	deleteUserFn     func(ctx context.Context, userID string, force bool) (*api.AdminGDPRDeletionResponse, error)
	listUserConsentFn func(ctx context.Context, userID string) (*api.GDPRConsentList, error)
}

func (m *mockAdminGDPRService) ExportUserData(ctx context.Context, userID string) (*api.AdminGDPRExportData, error) {
	if m.exportUserDataFn != nil {
		return m.exportUserDataFn(ctx, userID)
	}
	return &api.AdminGDPRExportData{
		UserID:     userID,
		Email:      "user@example.com",
		Name:       "Test User",
		CreatedAt:  time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Data:       map[string]interface{}{"sessions": []interface{}{}, "audit_logs": []interface{}{}},
		ExportedAt: time.Now().UTC(),
	}, nil
}

func (m *mockAdminGDPRService) DeleteUser(ctx context.Context, userID string, force bool) (*api.AdminGDPRDeletionResponse, error) {
	if m.deleteUserFn != nil {
		return m.deleteUserFn(ctx, userID, force)
	}
	msg := "user deletion scheduled"
	if force {
		msg = "user deleted immediately"
	}
	return &api.AdminGDPRDeletionResponse{
		Message: msg,
		UserID:  userID,
		Force:   force,
	}, nil
}

func (m *mockAdminGDPRService) ListUserConsent(ctx context.Context, userID string) (*api.GDPRConsentList, error) {
	if m.listUserConsentFn != nil {
		return m.listUserConsentFn(ctx, userID)
	}
	return &api.GDPRConsentList{
		Consents: []api.GDPRConsentRecord{
			{Type: "marketing", Granted: true, GrantedAt: time.Now().UTC()},
			{Type: "analytics", Granted: false, GrantedAt: time.Now().UTC()},
		},
	}, nil
}

// --- Helper ---

func newAdminGDPRRouter(gdprSvc api.AdminGDPRService) *gin.Engine {
	svc := &api.AdminServices{GDPR: gdprSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- Export tests ---

func TestAdminGDPRExport_Success(t *testing.T) {
	r := newAdminGDPRRouter(&mockAdminGDPRService{})
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/export", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminGDPRExportData
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.UserID)
	assert.Equal(t, "user@example.com", resp.Email)
	assert.NotNil(t, resp.Data)
}

func TestAdminGDPRExport_NotFound(t *testing.T) {
	svc := &mockAdminGDPRService{
		exportUserDataFn: func(_ context.Context, _ string) (*api.AdminGDPRExportData, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/nonexistent/export", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminGDPRExport_ServiceError(t *testing.T) {
	svc := &mockAdminGDPRService{
		exportUserDataFn: func(_ context.Context, _ string) (*api.AdminGDPRExportData, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newAdminGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/export", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Delete tests ---

func TestAdminGDPRDelete_Success(t *testing.T) {
	r := newAdminGDPRRouter(&mockAdminGDPRService{})
	w := doRequest(r, http.MethodDelete, "/admin/users/user-42/gdpr", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminGDPRDeletionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.UserID)
	assert.Equal(t, "user deletion scheduled", resp.Message)
	assert.False(t, resp.Force)
}

func TestAdminGDPRDelete_Force(t *testing.T) {
	r := newAdminGDPRRouter(&mockAdminGDPRService{})
	body := map[string]interface{}{"force": true}
	w := doRequest(r, http.MethodDelete, "/admin/users/user-42/gdpr", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminGDPRDeletionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user deleted immediately", resp.Message)
	assert.True(t, resp.Force)
}

func TestAdminGDPRDelete_NotFound(t *testing.T) {
	svc := &mockAdminGDPRService{
		deleteUserFn: func(_ context.Context, _ string, _ bool) (*api.AdminGDPRDeletionResponse, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminGDPRRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/users/nonexistent/gdpr", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- ListConsent tests ---

func TestAdminGDPRListConsent_Success(t *testing.T) {
	r := newAdminGDPRRouter(&mockAdminGDPRService{})
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/consent", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.GDPRConsentList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Len(t, resp.Consents, 2)
	assert.Equal(t, "marketing", resp.Consents[0].Type)
}

func TestAdminGDPRListConsent_NotFound(t *testing.T) {
	svc := &mockAdminGDPRService{
		listUserConsentFn: func(_ context.Context, _ string) (*api.GDPRConsentList, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/nonexistent/consent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminGDPRListConsent_ServiceError(t *testing.T) {
	svc := &mockAdminGDPRService{
		listUserConsentFn: func(_ context.Context, _ string) (*api.GDPRConsentList, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminGDPRRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/consent", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
