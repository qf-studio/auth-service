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
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminMFAService ---

type mockAdminMFAService struct {
	getMFAStatusFn func(ctx context.Context, userID string) (*api.AdminMFAStatus, error)
	resetMFAFn     func(ctx context.Context, userID string) error
}

func (m *mockAdminMFAService) GetMFAStatus(ctx context.Context, userID string) (*api.AdminMFAStatus, error) {
	if m.getMFAStatusFn != nil {
		return m.getMFAStatusFn(ctx, userID)
	}
	return &api.AdminMFAStatus{
		UserID:     userID,
		Enabled:    true,
		Type:       "totp",
		Confirmed:  true,
		BackupLeft: 8,
	}, nil
}

func (m *mockAdminMFAService) ResetMFA(ctx context.Context, userID string) error {
	if m.resetMFAFn != nil {
		return m.resetMFAFn(ctx, userID)
	}
	return nil
}

// --- Helper ---

func newAdminMFARouter(mfaSvc api.AdminMFAService) *gin.Engine {
	svc := &api.AdminServices{MFA: mfaSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- GetStatus tests ---

func TestAdminMFAGetStatus_Success(t *testing.T) {
	r := newAdminMFARouter(&mockAdminMFAService{})
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/mfa", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminMFAStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user-42", resp.UserID)
	assert.True(t, resp.Enabled)
	assert.Equal(t, "totp", resp.Type)
	assert.True(t, resp.Confirmed)
	assert.Equal(t, 8, resp.BackupLeft)
}

func TestAdminMFAGetStatus_NotFound(t *testing.T) {
	svc := &mockAdminMFAService{
		getMFAStatusFn: func(_ context.Context, _ string) (*api.AdminMFAStatus, error) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminMFARouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/nonexistent/mfa", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminMFAGetStatus_ServiceError(t *testing.T) {
	svc := &mockAdminMFAService{
		getMFAStatusFn: func(_ context.Context, _ string) (*api.AdminMFAStatus, error) {
			return nil, fmt.Errorf("db failure: %w", api.ErrInternalError)
		},
	}
	r := newAdminMFARouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/users/user-42/mfa", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Reset tests ---

func TestAdminMFAReset_Success(t *testing.T) {
	r := newAdminMFARouter(&mockAdminMFAService{})
	w := doRequest(r, http.MethodDelete, "/admin/users/user-42/mfa", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "MFA reset", resp["message"])
}

func TestAdminMFAReset_NotFound(t *testing.T) {
	svc := &mockAdminMFAService{
		resetMFAFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("user not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminMFARouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/users/nonexistent/mfa", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminMFAReset_ServiceError(t *testing.T) {
	svc := &mockAdminMFAService{
		resetMFAFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("internal failure: %w", api.ErrInternalError)
		},
	}
	r := newAdminMFARouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/users/user-42/mfa", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Routes not registered when service is nil ---

func TestAdminMFARoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.AdminServices{} // MFA is nil
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})

	w := doRequest(r, http.MethodGet, "/admin/users/user-42/mfa", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = doRequest(r, http.MethodDelete, "/admin/users/user-42/mfa", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}
