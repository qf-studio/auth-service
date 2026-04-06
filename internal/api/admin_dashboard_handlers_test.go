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

// --- Mock AdminDashboardService ---

type mockDashboardService struct {
	overviewFn      func(ctx context.Context) (*api.DashboardOverview, error)
	securityFn      func(ctx context.Context) (*api.DashboardSecurity, error)
	listAuditLogsFn func(ctx context.Context, page, perPage int, action, actorID, severity string, startDate, endDate *time.Time) (*api.AuditLogList, error)
}

func (m *mockDashboardService) Overview(ctx context.Context) (*api.DashboardOverview, error) {
	if m.overviewFn != nil {
		return m.overviewFn(ctx)
	}
	return &api.DashboardOverview{
		ActiveSessions:  42,
		ActiveUsers24h:  7,
		TotalUsers:      100,
		TotalClients:    5,
		AuthSuccessRate: 95.5,
		MFAAdoptionRate: 30.0,
		SystemHealth:    "healthy",
	}, nil
}

func (m *mockDashboardService) Security(ctx context.Context) (*api.DashboardSecurity, error) {
	if m.securityFn != nil {
		return m.securityFn(ctx)
	}
	return &api.DashboardSecurity{
		FailedLogins24h:      15,
		TopTargetedAccounts:  []api.AuditCountItem{{ID: "user-1", Count: 10}},
		TopSourceIPs:         []api.AuditCountItem{{ID: "192.168.1.1", Count: 8}},
		LockedAccounts:       2,
		RecentSecurityEvents: []api.AuditLogEntry{},
	}, nil
}

func (m *mockDashboardService) ListAuditLogs(ctx context.Context, page, perPage int, action, actorID, severity string, startDate, endDate *time.Time) (*api.AuditLogList, error) {
	if m.listAuditLogsFn != nil {
		return m.listAuditLogsFn(ctx, page, perPage, action, actorID, severity, startDate, endDate)
	}
	return &api.AuditLogList{
		Entries: []api.AuditLogEntry{
			{ID: "log-1", EventType: "login_success", CreatedAt: time.Now()},
		},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

// --- Helper ---

func newDashboardRouter(dashSvc api.AdminDashboardService) *gin.Engine {
	svc := &api.AdminServices{Dashboard: dashSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- Overview ---

func TestAdminDashboardOverview_Success(t *testing.T) {
	r := newDashboardRouter(&mockDashboardService{})
	w := doRequest(r, http.MethodGet, "/admin/dashboard/overview", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.DashboardOverview
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(42), resp.ActiveSessions)
	assert.Equal(t, int64(7), resp.ActiveUsers24h)
	assert.Equal(t, 100, resp.TotalUsers)
	assert.Equal(t, 5, resp.TotalClients)
	assert.Equal(t, 95.5, resp.AuthSuccessRate)
	assert.Equal(t, 30.0, resp.MFAAdoptionRate)
	assert.Equal(t, "healthy", resp.SystemHealth)
}

func TestAdminDashboardOverview_ServiceError(t *testing.T) {
	svc := &mockDashboardService{
		overviewFn: func(_ context.Context) (*api.DashboardOverview, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newDashboardRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/dashboard/overview", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Security ---

func TestAdminDashboardSecurity_Success(t *testing.T) {
	r := newDashboardRouter(&mockDashboardService{})
	w := doRequest(r, http.MethodGet, "/admin/dashboard/security", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.DashboardSecurity
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, int64(15), resp.FailedLogins24h)
	assert.Len(t, resp.TopTargetedAccounts, 1)
	assert.Len(t, resp.TopSourceIPs, 1)
	assert.Equal(t, 2, resp.LockedAccounts)
}

func TestAdminDashboardSecurity_ServiceError(t *testing.T) {
	svc := &mockDashboardService{
		securityFn: func(_ context.Context) (*api.DashboardSecurity, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newDashboardRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/dashboard/security", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Audit Logs ---

func TestAdminAuditLogs_Success(t *testing.T) {
	r := newDashboardRouter(&mockDashboardService{})
	w := doRequest(r, http.MethodGet, "/admin/audit-logs", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuditLogList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Entries, 1)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 20, resp.PerPage)
}

func TestAdminAuditLogs_WithFilters(t *testing.T) {
	svc := &mockDashboardService{
		listAuditLogsFn: func(_ context.Context, page, perPage int, action, actorID, severity string, startDate, endDate *time.Time) (*api.AuditLogList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "login_failure", action)
			assert.Equal(t, "user-42", actorID)
			assert.Equal(t, "warning", severity)
			require.NotNil(t, startDate)
			require.NotNil(t, endDate)
			return &api.AuditLogList{Entries: []api.AuditLogEntry{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newDashboardRouter(svc)
	w := doRequest(r, http.MethodGet,
		"/admin/audit-logs?page=2&per_page=10&action=login_failure&user_id=user-42&severity=warning&start_date=2026-04-01T00:00:00Z&end_date=2026-04-06T00:00:00Z",
		nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminAuditLogs_InvalidStartDate(t *testing.T) {
	r := newDashboardRouter(&mockDashboardService{})
	w := doRequest(r, http.MethodGet, "/admin/audit-logs?start_date=invalid", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminAuditLogs_InvalidEndDate(t *testing.T) {
	r := newDashboardRouter(&mockDashboardService{})
	w := doRequest(r, http.MethodGet, "/admin/audit-logs?end_date=not-a-date", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminAuditLogs_ServiceError(t *testing.T) {
	svc := &mockDashboardService{
		listAuditLogsFn: func(_ context.Context, _, _ int, _, _, _ string, _, _ *time.Time) (*api.AuditLogList, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newDashboardRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit-logs", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
