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

// --- Mock AdminAuditService ---

type mockAdminAuditService struct {
	listEventsFn func(ctx context.Context, page, perPage int, filter api.AuditFilter) (*api.AdminAuditList, error)
}

func (m *mockAdminAuditService) ListEvents(ctx context.Context, page, perPage int, filter api.AuditFilter) (*api.AdminAuditList, error) {
	if m.listEventsFn != nil {
		return m.listEventsFn(ctx, page, perPage, filter)
	}
	return &api.AdminAuditList{
		Events:  []api.AdminAuditEvent{},
		Total:   0,
		Page:    page,
		PerPage: perPage,
	}, nil
}

// --- Helper ---

func setupAuditRouter(auditSvc api.AdminAuditService) *gin.Engine {
	svc := &api.AdminServices{Audit: auditSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List audit events: defaults ---

func TestAdminListAudit_Success(t *testing.T) {
	now := time.Date(2026, 1, 15, 10, 30, 0, 0, time.UTC)
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, page, perPage int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, 1, page)
			assert.Equal(t, 20, perPage)
			assert.Empty(t, filter.UserID)
			assert.Empty(t, filter.ClientID)
			assert.Empty(t, filter.EventType)
			assert.Nil(t, filter.StartDate)
			assert.Nil(t, filter.EndDate)
			return &api.AdminAuditList{
				Events: []api.AdminAuditEvent{
					{ID: "ev-1", UserID: "u1", EventType: "login_success", CreatedAt: now},
					{ID: "ev-2", UserID: "u2", EventType: "login_failure", CreatedAt: now.Add(-time.Hour)},
				},
				Total:   2,
				Page:    page,
				PerPage: perPage,
			}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAuditList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Total)
	assert.Len(t, resp.Events, 2)
	assert.Equal(t, 1, resp.Page)
	assert.Equal(t, 20, resp.PerPage)
	assert.Equal(t, "ev-1", resp.Events[0].ID)
	assert.Equal(t, "login_success", resp.Events[0].EventType)
}

// --- Empty results ---

func TestAdminListAudit_EmptyResults(t *testing.T) {
	svc := &mockAdminAuditService{}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAuditList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.Events)
}

// --- Pagination ---

func TestAdminListAudit_Pagination(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, page, perPage int, _ api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, 3, page)
			assert.Equal(t, 5, perPage)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?page=3&per_page=5", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAuditList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.Page)
	assert.Equal(t, 5, resp.PerPage)
	assert.Equal(t, 50, resp.Total)
}

func TestAdminListAudit_PaginationClampNegativePage(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, page, perPage int, _ api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, 1, page)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?page=-5", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListAudit_PaginationClampPerPageMax(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, perPage int, _ api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, 100, perPage)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: perPage}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?per_page=500", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Filter: user_id ---

func TestAdminListAudit_FilterByUserID(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, "user-42", filter.UserID)
			return &api.AdminAuditList{
				Events: []api.AdminAuditEvent{
					{ID: "ev-1", UserID: "user-42", EventType: "login_success", CreatedAt: time.Now()},
				},
				Total: 1, Page: 1, PerPage: 20,
			}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?user_id=user-42", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAuditList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Equal(t, "user-42", resp.Events[0].UserID)
}

// --- Filter: event_type ---

func TestAdminListAudit_FilterByEventType(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, "login_failure", filter.EventType)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?event_type=login_failure", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Filter: client_id ---

func TestAdminListAudit_FilterByClientID(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, "client-abc", filter.ClientID)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit?client_id=client-abc", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Filter: date range ---

func TestAdminListAudit_FilterByDateRange(t *testing.T) {
	startStr := "2026-01-01T00:00:00Z"
	endStr := "2026-01-31T23:59:59Z"
	expectedStart, _ := time.Parse(time.RFC3339, startStr)
	expectedEnd, _ := time.Parse(time.RFC3339, endStr)

	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			require.NotNil(t, filter.StartDate)
			require.NotNil(t, filter.EndDate)
			assert.True(t, expectedStart.Equal(*filter.StartDate))
			assert.True(t, expectedEnd.Equal(*filter.EndDate))
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, fmt.Sprintf("/admin/audit?start_date=%s&end_date=%s", startStr, endStr), nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListAudit_InvalidStartDate(t *testing.T) {
	r := setupAuditRouter(&mockAdminAuditService{})
	w := doRequest(r, http.MethodGet, "/admin/audit?start_date=not-a-date", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminListAudit_InvalidEndDate(t *testing.T) {
	r := setupAuditRouter(&mockAdminAuditService{})
	w := doRequest(r, http.MethodGet, "/admin/audit?end_date=2026-13-99", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Combined filters ---

func TestAdminListAudit_CombinedFilters(t *testing.T) {
	startStr := "2026-03-01T00:00:00Z"
	expectedStart, _ := time.Parse(time.RFC3339, startStr)

	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, page, perPage int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "user-7", filter.UserID)
			assert.Equal(t, "client-x", filter.ClientID)
			assert.Equal(t, "password_change", filter.EventType)
			require.NotNil(t, filter.StartDate)
			assert.True(t, expectedStart.Equal(*filter.StartDate))
			assert.Nil(t, filter.EndDate)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, fmt.Sprintf(
		"/admin/audit?page=2&per_page=10&user_id=user-7&client_id=client-x&event_type=password_change&start_date=%s",
		startStr,
	), nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Service error ---

func TestAdminListAudit_ServiceError(t *testing.T) {
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, _ api.AuditFilter) (*api.AdminAuditList, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Response structure ---

func TestAdminListAudit_ResponseContainsAllFields(t *testing.T) {
	now := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, _ api.AuditFilter) (*api.AdminAuditList, error) {
			return &api.AdminAuditList{
				Events: []api.AdminAuditEvent{
					{
						ID:        "ev-full",
						UserID:    "u1",
						ClientID:  "c1",
						EventType: "token_refresh",
						IPAddress: "10.0.0.1",
						UserAgent: "Go-http-client/1.1",
						Metadata:  map[string]string{"scope": "read"},
						CreatedAt: now,
					},
				},
				Total: 1, Page: 1, PerPage: 20,
			}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/audit", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAuditList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Events, 1)

	ev := resp.Events[0]
	assert.Equal(t, "ev-full", ev.ID)
	assert.Equal(t, "u1", ev.UserID)
	assert.Equal(t, "c1", ev.ClientID)
	assert.Equal(t, "token_refresh", ev.EventType)
	assert.Equal(t, "10.0.0.1", ev.IPAddress)
	assert.Equal(t, "Go-http-client/1.1", ev.UserAgent)
	assert.Equal(t, "read", ev.Metadata["scope"])
	assert.True(t, now.Equal(ev.CreatedAt))
}

// --- Only start_date filter ---

func TestAdminListAudit_FilterByStartDateOnly(t *testing.T) {
	startStr := "2026-02-15T08:00:00Z"
	expectedStart, _ := time.Parse(time.RFC3339, startStr)

	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			require.NotNil(t, filter.StartDate)
			assert.True(t, expectedStart.Equal(*filter.StartDate))
			assert.Nil(t, filter.EndDate)
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, fmt.Sprintf("/admin/audit?start_date=%s", startStr), nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Only end_date filter ---

func TestAdminListAudit_FilterByEndDateOnly(t *testing.T) {
	endStr := "2026-06-30T23:59:59Z"
	expectedEnd, _ := time.Parse(time.RFC3339, endStr)

	svc := &mockAdminAuditService{
		listEventsFn: func(_ context.Context, _, _ int, filter api.AuditFilter) (*api.AdminAuditList, error) {
			assert.Nil(t, filter.StartDate)
			require.NotNil(t, filter.EndDate)
			assert.True(t, expectedEnd.Equal(*filter.EndDate))
			return &api.AdminAuditList{Events: []api.AdminAuditEvent{}, Total: 0, Page: 1, PerPage: 20}, nil
		},
	}
	r := setupAuditRouter(svc)
	w := doRequest(r, http.MethodGet, fmt.Sprintf("/admin/audit?end_date=%s", endStr), nil)

	assert.Equal(t, http.StatusOK, w.Code)
}
