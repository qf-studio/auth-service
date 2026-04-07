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
		Tenants: []api.AdminTenant{
			{ID: "t1", Name: "Acme", Slug: "acme", Status: "active", Config: domain.TenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminTenantService) GetTenant(ctx context.Context, tenantID string) (*api.AdminTenant, error) {
	if m.getTenantFn != nil {
		return m.getTenantFn(ctx, tenantID)
	}
	return &api.AdminTenant{ID: tenantID, Name: "Acme", Slug: "acme", Status: "active", Config: domain.TenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminTenantService) CreateTenant(ctx context.Context, req *api.CreateTenantRequest) (*api.AdminTenant, error) {
	if m.createTenantFn != nil {
		return m.createTenantFn(ctx, req)
	}
	return &api.AdminTenant{ID: "new-tenant", Name: req.Name, Slug: req.Slug, Status: "active", Config: req.Config, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminTenantService) UpdateTenant(ctx context.Context, tenantID string, req *api.UpdateTenantRequest) (*api.AdminTenant, error) {
	if m.updateTenantFn != nil {
		return m.updateTenantFn(ctx, tenantID, req)
	}
	name := "Acme"
	if req.Name != nil {
		name = *req.Name
	}
	return &api.AdminTenant{ID: tenantID, Name: name, Slug: "acme", Status: "active", Config: domain.TenantConfig{}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
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
	assert.Equal(t, "Acme", resp.Tenants[0].Name)
}

func TestAdminListTenants_Pagination(t *testing.T) {
	svc := &mockAdminTenantService{
		listTenantsFn: func(_ context.Context, page, perPage int, status string) (*api.AdminTenantList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "active", status)
			return &api.AdminTenantList{Tenants: []api.AdminTenant{}, Total: 25, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/tenants?page=2&per_page=10&status=active", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenantList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
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
			return nil, fmt.Errorf("not found: %w", api.ErrNotFound)
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
		"name": "New Tenant",
		"slug": "newtenant",
	}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminTenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "New Tenant", resp.Name)
	assert.Equal(t, "newtenant", resp.Slug)
}

func TestAdminCreateTenant_InvalidBody(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	w := doRequest(r, http.MethodPost, "/admin/tenants", "not-json")

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateTenant_MissingFields(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{"name": "No Slug"}
	w := doRequest(r, http.MethodPost, "/admin/tenants", body)

	// Validation errors return 422 Unprocessable Entity.
	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// --- Update Tenant ---

func TestAdminUpdateTenant_Success(t *testing.T) {
	r := newAdminTenantRouter(&mockAdminTenantService{})
	body := map[string]interface{}{"name": "Updated Name"}
	w := doRequest(r, http.MethodPatch, "/admin/tenants/tenant-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminTenant
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Updated Name", resp.Name)
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
			return fmt.Errorf("not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminTenantRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/tenants/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
