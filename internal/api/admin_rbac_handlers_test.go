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

// --- Mock AdminRBACService ---

type mockAdminRBACService struct {
	listPoliciesFn func(ctx context.Context) (*api.AdminPolicyList, error)
	createPolicyFn func(ctx context.Context, req *api.CreatePolicyRequest) (*api.AdminPolicy, error)
	deletePolicyFn func(ctx context.Context, req *api.DeletePolicyRequest) error
	getUserRolesFn func(ctx context.Context, user string) (*api.AdminUserRoles, error)
	assignRoleFn   func(ctx context.Context, req *api.AssignRoleRequest) (*api.AdminUserRoles, error)
}

func (m *mockAdminRBACService) ListPolicies(ctx context.Context) (*api.AdminPolicyList, error) {
	if m.listPoliciesFn != nil {
		return m.listPoliciesFn(ctx)
	}
	return &api.AdminPolicyList{
		Policies: []api.AdminPolicy{{Subject: "user:alice", Object: "/api/data", Action: "read"}},
		Total:    1,
	}, nil
}

func (m *mockAdminRBACService) CreatePolicy(ctx context.Context, req *api.CreatePolicyRequest) (*api.AdminPolicy, error) {
	if m.createPolicyFn != nil {
		return m.createPolicyFn(ctx, req)
	}
	return &api.AdminPolicy{Subject: req.Subject, Object: req.Object, Action: req.Action}, nil
}

func (m *mockAdminRBACService) DeletePolicy(ctx context.Context, req *api.DeletePolicyRequest) error {
	if m.deletePolicyFn != nil {
		return m.deletePolicyFn(ctx, req)
	}
	return nil
}

func (m *mockAdminRBACService) GetUserRoles(ctx context.Context, user string) (*api.AdminUserRoles, error) {
	if m.getUserRolesFn != nil {
		return m.getUserRolesFn(ctx, user)
	}
	return &api.AdminUserRoles{User: user, Roles: []string{"admin"}}, nil
}

func (m *mockAdminRBACService) AssignRole(ctx context.Context, req *api.AssignRoleRequest) (*api.AdminUserRoles, error) {
	if m.assignRoleFn != nil {
		return m.assignRoleFn(ctx, req)
	}
	return &api.AdminUserRoles{User: req.User, Roles: []string{req.Role}}, nil
}

// --- Helper ---

func newAdminRBACRouter(rbacSvc api.AdminRBACService) *gin.Engine {
	svc := &api.AdminServices{RBAC: rbacSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List Policies ---

func TestAdminListPolicies_Success(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	w := doRequest(r, http.MethodGet, "/admin/rbac/policies", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminPolicyList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Policies, 1)
	assert.Equal(t, "user:alice", resp.Policies[0].Subject)
}

func TestAdminListPolicies_Empty(t *testing.T) {
	svc := &mockAdminRBACService{
		listPoliciesFn: func(_ context.Context) (*api.AdminPolicyList, error) {
			return &api.AdminPolicyList{Policies: []api.AdminPolicy{}, Total: 0}, nil
		},
	}
	r := newAdminRBACRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rbac/policies", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminPolicyList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 0, resp.Total)
	assert.Empty(t, resp.Policies)
}

func TestAdminListPolicies_ServiceError(t *testing.T) {
	svc := &mockAdminRBACService{
		listPoliciesFn: func(_ context.Context) (*api.AdminPolicyList, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminRBACRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rbac/policies", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Create Policy ---

func TestAdminCreatePolicy_Success(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	body := map[string]string{
		"subject": "user:alice",
		"object":  "/api/data",
		"action":  "read",
	}
	w := doRequest(r, http.MethodPost, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminPolicy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user:alice", resp.Subject)
	assert.Equal(t, "/api/data", resp.Object)
	assert.Equal(t, "read", resp.Action)
}

func TestAdminCreatePolicy_ValidationError(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	// Missing required fields
	body := map[string]string{"subject": "user:alice"}
	w := doRequest(r, http.MethodPost, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreatePolicy_InvalidJSON(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	w := doRequest(r, http.MethodPost, "/admin/rbac/policies", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreatePolicy_ServiceError(t *testing.T) {
	svc := &mockAdminRBACService{
		createPolicyFn: func(_ context.Context, _ *api.CreatePolicyRequest) (*api.AdminPolicy, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminRBACRouter(svc)
	body := map[string]string{"subject": "user:alice", "object": "/api/data", "action": "read"}
	w := doRequest(r, http.MethodPost, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Delete Policy ---

func TestAdminDeletePolicy_Success(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	body := map[string]string{
		"subject": "user:alice",
		"object":  "/api/data",
		"action":  "read",
	}
	w := doRequest(r, http.MethodDelete, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "policy deleted", resp["message"])
}

func TestAdminDeletePolicy_NotFound(t *testing.T) {
	svc := &mockAdminRBACService{
		deletePolicyFn: func(_ context.Context, _ *api.DeletePolicyRequest) error {
			return fmt.Errorf("policy not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminRBACRouter(svc)
	body := map[string]string{"subject": "user:alice", "object": "/api/data", "action": "read"}
	w := doRequest(r, http.MethodDelete, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminDeletePolicy_ValidationError(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	body := map[string]string{"subject": "user:alice"}
	w := doRequest(r, http.MethodDelete, "/admin/rbac/policies", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminDeletePolicy_InvalidJSON(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	w := doRequest(r, http.MethodDelete, "/admin/rbac/policies", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Get User Roles ---

func TestAdminGetUserRoles_Success(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	w := doRequest(r, http.MethodGet, "/admin/rbac/roles/user:alice", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUserRoles
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user:alice", resp.User)
	assert.Contains(t, resp.Roles, "admin")
}

func TestAdminGetUserRoles_NoRoles(t *testing.T) {
	svc := &mockAdminRBACService{
		getUserRolesFn: func(_ context.Context, user string) (*api.AdminUserRoles, error) {
			return &api.AdminUserRoles{User: user, Roles: []string{}}, nil
		},
	}
	r := newAdminRBACRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rbac/roles/user:bob", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminUserRoles
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user:bob", resp.User)
	assert.Empty(t, resp.Roles)
}

func TestAdminGetUserRoles_ServiceError(t *testing.T) {
	svc := &mockAdminRBACService{
		getUserRolesFn: func(_ context.Context, _ string) (*api.AdminUserRoles, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminRBACRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rbac/roles/user:alice", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Assign Role ---

func TestAdminAssignRole_Success(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	body := map[string]string{
		"user": "user:alice",
		"role": "editor",
	}
	w := doRequest(r, http.MethodPost, "/admin/rbac/roles", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminUserRoles
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "user:alice", resp.User)
	assert.Contains(t, resp.Roles, "editor")
}

func TestAdminAssignRole_ValidationError(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	body := map[string]string{"user": "user:alice"}
	w := doRequest(r, http.MethodPost, "/admin/rbac/roles", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminAssignRole_InvalidJSON(t *testing.T) {
	r := newAdminRBACRouter(&mockAdminRBACService{})
	w := doRequest(r, http.MethodPost, "/admin/rbac/roles", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminAssignRole_ServiceError(t *testing.T) {
	svc := &mockAdminRBACService{
		assignRoleFn: func(_ context.Context, _ *api.AssignRoleRequest) (*api.AdminUserRoles, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminRBACRouter(svc)
	body := map[string]string{"user": "user:alice", "role": "editor"}
	w := doRequest(r, http.MethodPost, "/admin/rbac/roles", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
