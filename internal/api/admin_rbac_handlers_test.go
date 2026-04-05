package api_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// --- mock AdminRBACService ---

type mockAdminRBACService struct {
	policies []api.RBACPolicy
	roles    map[string][]string
	addErr   error
	rmErr    error
}

func newMockAdminRBACService() *mockAdminRBACService {
	return &mockAdminRBACService{roles: make(map[string][]string)}
}

func (m *mockAdminRBACService) ListPolicies(_ context.Context) ([]api.RBACPolicy, error) {
	if m.policies == nil {
		return []api.RBACPolicy{}, nil
	}
	return m.policies, nil
}

func (m *mockAdminRBACService) AddPolicy(_ context.Context, sub, obj, act string) error {
	if m.addErr != nil {
		return m.addErr
	}
	m.policies = append(m.policies, api.RBACPolicy{Subject: sub, Object: obj, Action: act})
	return nil
}

func (m *mockAdminRBACService) RemovePolicy(_ context.Context, sub, obj, act string) error {
	if m.rmErr != nil {
		return m.rmErr
	}
	filtered := m.policies[:0]
	for _, p := range m.policies {
		if p.Subject != sub || p.Object != obj || p.Action != act {
			filtered = append(filtered, p)
		}
	}
	m.policies = filtered
	return nil
}

func (m *mockAdminRBACService) GetRolesForUser(_ context.Context, userID string) ([]string, error) {
	return m.roles[userID], nil
}

func (m *mockAdminRBACService) AssignRole(_ context.Context, userID, role string) error {
	m.roles[userID] = append(m.roles[userID], role)
	return nil
}

func (m *mockAdminRBACService) RemoveRole(_ context.Context, userID, role string) error {
	existing := m.roles[userID]
	filtered := existing[:0]
	for _, r := range existing {
		if r != role {
			filtered = append(filtered, r)
		}
	}
	m.roles[userID] = filtered
	return nil
}

// --- helpers ---

func newRBACRouter(svc api.AdminRBACService) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.CorrelationID())

	h := api.NewAdminRBACHandlers(svc)
	rbac := r.Group("/admin/rbac")
	{
		rbac.GET("/policies", h.ListPolicies)
		rbac.POST("/policies", h.AddPolicy)
		rbac.DELETE("/policies", h.RemovePolicy)
		rbac.GET("/roles/:user_id", h.GetRoles)
		rbac.POST("/roles/:user_id", h.AssignRole)
		rbac.DELETE("/roles/:user_id", h.RemoveRole)
	}
	return r
}

func rbacJSON(t *testing.T, v interface{}) *bytes.Buffer {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return bytes.NewBuffer(b)
}

// --- ListPolicies ---

func TestAdminRBAC_ListPolicies(t *testing.T) {
	svc := newMockAdminRBACService()
	svc.policies = []api.RBACPolicy{
		{Subject: "alice", Object: "/tokens", Action: "read"},
	}

	r := newRBACRouter(svc)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/rbac/policies", http.NoBody))

	assert.Equal(t, http.StatusOK, w.Code)

	var resp struct {
		Policies []api.RBACPolicy `json:"policies"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Len(t, resp.Policies, 1)
	assert.Equal(t, "alice", resp.Policies[0].Subject)
}

func TestAdminRBAC_ListPolicies_Empty(t *testing.T) {
	r := newRBACRouter(newMockAdminRBACService())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/rbac/policies", http.NoBody))
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- AddPolicy ---

func TestAdminRBAC_AddPolicy(t *testing.T) {
	svc := newMockAdminRBACService()
	r := newRBACRouter(svc)

	body := rbacJSON(t, api.AdminRBACPolicyRequest{Subject: "bob", Object: "/clients", Action: "write"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/rbac/policies", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Len(t, svc.policies, 1)
	assert.Equal(t, "bob", svc.policies[0].Subject)
}

func TestAdminRBAC_AddPolicy_MissingField(t *testing.T) {
	r := newRBACRouter(newMockAdminRBACService())

	body := rbacJSON(t, map[string]string{"sub": "bob"}) // missing obj and act
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/rbac/policies", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// --- RemovePolicy ---

func TestAdminRBAC_RemovePolicy(t *testing.T) {
	svc := newMockAdminRBACService()
	svc.policies = []api.RBACPolicy{
		{Subject: "alice", Object: "/tokens", Action: "read"},
	}
	r := newRBACRouter(svc)

	body := rbacJSON(t, api.AdminRBACPolicyRequest{Subject: "alice", Object: "/tokens", Action: "read"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/rbac/policies", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, svc.policies)
}

// --- GetRoles ---

func TestAdminRBAC_GetRoles(t *testing.T) {
	svc := newMockAdminRBACService()
	svc.roles["user-123"] = []string{"admin", "operator"}
	r := newRBACRouter(svc)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin/rbac/roles/user-123", http.NoBody))

	assert.Equal(t, http.StatusOK, w.Code)
	var resp struct {
		UserID string   `json:"user_id"`
		Roles  []string `json:"roles"`
	}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "user-123", resp.UserID)
	assert.ElementsMatch(t, []string{"admin", "operator"}, resp.Roles)
}

// --- AssignRole ---

func TestAdminRBAC_AssignRole(t *testing.T) {
	svc := newMockAdminRBACService()
	r := newRBACRouter(svc)

	body := rbacJSON(t, api.AdminRBACRoleRequest{Role: "admin"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/rbac/roles/user-456", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Contains(t, svc.roles["user-456"], "admin")
}

func TestAdminRBAC_AssignRole_MissingRole(t *testing.T) {
	r := newRBACRouter(newMockAdminRBACService())

	body := rbacJSON(t, map[string]string{}) // missing role field
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/admin/rbac/roles/user-456", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

// --- RemoveRole ---

func TestAdminRBAC_RemoveRole(t *testing.T) {
	svc := newMockAdminRBACService()
	svc.roles["user-789"] = []string{"admin"}
	r := newRBACRouter(svc)

	body := rbacJSON(t, api.AdminRBACRoleRequest{Role: "admin"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/admin/rbac/roles/user-789", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, svc.roles["user-789"])
}
