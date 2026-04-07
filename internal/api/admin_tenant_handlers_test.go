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

// --- Mock AdminTenantService ---

type mockAdminTenantService struct {
	listTenantsFn  func(ctx context.Context, page, perPage int, status string) (*api.AdminTenantList, error)
	getTenantFn    func(ctx context.Context, tenantID string) (*api.AdminTenant, error)
	createTenantFn func(ctx context.Context, req *api.CreateTenantRequest) (*api.AdminTenant, error)
	updateTenantFn func(ctx context.Context, tenantID string, req *api.UpdateTenantRequest) (*api.AdminTenant, error)
	deleteTenantFn func(ctx context.Context, tenantID string) error
}

func (m *mockAdminTenantService) ListTenants(ctx context.Context, page, perPage int, status string) (*api.AdminTenantList, error) {
	if m.listTenantsFn != nil {
		return m.listTenantsFn(ctx, page, perPage, status)
	}
	return &api.AdminTenantList{
		Tenants: []api.AdminTenant{{ID: "t1", Name: "default", Slug: "default", Status: "active", Config: api.AdminTenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminTenantService) GetTenant(ctx context.Context, tenantID string) (*api.AdminTenant, error) {
	if m.getTenantFn != nil {
		return m.getTenantFn(ctx, tenantID)
	}
	return &api.AdminTenant{ID: tenantID, Name: "default", Slug: "default", Status: "active", Config: api.AdminTenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminTenantService) CreateTenant(ctx context.Context, req *api.CreateTenantRequest) (*api.AdminTenant, error) {
	if m.createTenantFn != nil {
		return m.createTenantFn(ctx, req)
	}
	cfg := api.AdminTenantConfig{}
	if req.Config != nil {
		cfg = *req.Config
	}
	return &api.AdminTenant{
		ID:        "new-tenant",
		Name:      req.Name,
		Slug:      req.Slug,
		Config:    cfg,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (m *mockAdminTenantService) UpdateTenant(ctx context.Context, tenantID string, req *api.UpdateTenantRequest) (*api.AdminTenant, error) {
	if m.updateTenantFn != nil {
		return m.updateTenantFn(ctx, tenantID, req)
	}
	name := "default"
	if req.Name != nil {
		name = *req.Name
	}
	return &api.AdminTenant{ID: tenantID, Name: name, Slug: "default", Status: "active", Config: api.AdminTenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminTenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	if m.deleteTenantFn != nil {
		return m.deleteTenantFn(ctx, tenantID)
	}
	return nil
}

// --- Helper ---

func newAdminTenantRouter(tenantSvc api.AdminTenantService) *gin.Engine {
	svc := &api.AdminServices{Tenants: tenantSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List Tenants ---

func TestAdminListTenants_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodGet, "/admin/tenants", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenantList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Tenants, 1)
}

func TestAdminListTenants_Pagination(t *testing.T) {
	svc := &mockAdminTenantService{
		listTenantsFn: func(_ context.Context, page, perPage int, status string) (*api.AdminTenantList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "", status)
			return &api.AdminTenantList{Tenants: []api.AdminTenant{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenantList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListTenants_StatusFilter(t *testing.T) {
	svc := &mockAdminTenantService{
		listTenantsFn: func(_ context.Context, page, perPage int, status string) (*api.AdminTenantList, error) {
			assert.Equal(t, "active", status)
			return &api.AdminTenantList{Tenants: []api.AdminTenant{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants?status=active", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListTenants_PerPageCapped(t *testing.T) {
	svc := &mockAdminTenantService{
		listTenantsFn: func(_ context.Context, page, perPage int, _ string) (*api.AdminTenantList, error) {
			assert.Equal(t, 1, page)
			assert.Equal(t, 100, perPage) // Capped at 100
			return &api.AdminTenantList{Tenants: []api.AdminTenant{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants?per_page=999", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListTenants_ServiceError(t *testing.T) {
	svc := &mockAdminTenantService{
		listTenantsFn: func(_ context.Context, _, _ int, _ string) (*api.AdminTenantList, error) {
			return nil, fmt.Errorf("database error")
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get Tenant ---

func TestAdminGetTenant_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodGet, "/admin/tenants/tenant-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tenant-1", resp.ID)
}

func TestAdminGetTenant_NotFound(t *testing.T) {
	svc := &mockAdminTenantService{
		getTenantFn: func(_ context.Context, _ string) (*api.AdminTenant, error) {
			return nil, fmt.Errorf("tenant not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create Tenant ---

func TestAdminCreateTenant_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{
		"name": "acme-corp",
		"slug": "acmecorp",
	}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminTenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "acme-corp", resp.Name)
	assert.Equal(t, "acmecorp", resp.Slug)
}

func TestAdminCreateTenant_MissingName(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{
		"slug": "nope",
	}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateTenant_MissingSlug(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{
		"name": "acme-corp",
	}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateTenant_InvalidJSON(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodPost, "/admin/tenants", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateTenant_Conflict(t *testing.T) {
	svc := &mockAdminTenantService{
		createTenantFn: func(_ context.Context, _ *api.CreateTenantRequest) (*api.AdminTenant, error) {
			return nil, fmt.Errorf("slug already exists: %w", api.ErrConflict)
		},
	}
	r := newAdminTenantRouter(svc)
	body := map[string]interface{}{
		"name": "acme-corp",
		"slug": "acmecorp",
	}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update Tenant ---

func TestAdminUpdateTenant_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{"name": "updated-name"}
	w := doRequest(r, http.MethodPatch, "/admin/tenants/tenant-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "updated-name", resp.Name)
}

func TestAdminUpdateTenant_NotFound(t *testing.T) {
	svc := &mockAdminTenantService{
		updateTenantFn: func(_ context.Context, _ string, _ *api.UpdateTenantRequest) (*api.AdminTenant, error) {
			return nil, fmt.Errorf("tenant not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminTenantRouter(svc)
	body := map[string]interface{}{"name": "nope"}
	w := doRequest(r, http.MethodPatch, "/admin/tenants/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdateTenant_InvalidJSON(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodPatch, "/admin/tenants/tenant-1", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUpdateTenant_InvalidStatus(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{"status": "invalid"}
	w := doRequest(r, http.MethodPatch, "/admin/tenants/tenant-1", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// --- Delete Tenant ---

func TestAdminDeleteTenant_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodDelete, "/admin/tenants/tenant-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteTenant_NotFound(t *testing.T) {
	svc := &mockAdminTenantService{
		deleteTenantFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("tenant not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/tenants/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminDeleteTenant_AlreadyDeleted(t *testing.T) {
	svc := &mockAdminTenantService{
		deleteTenantFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("tenant already deleted: %w", api.ErrConflict)
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/tenants/deleted-tenant", nil)

	assert.Equal(t, http.StatusConflict, w.Code)
}
