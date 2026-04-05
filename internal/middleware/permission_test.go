package middleware_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// --- mock PermissionEnforcer ---

// mockEnforcer is a PermissionEnforcer that allows any policy to be set at
// construction time. Thread-unsafe; safe for serial tests only.
type mockEnforcer struct {
	allowed map[string]bool // key: "sub|obj|act"
	err     error           // if non-nil, CheckPermission returns this error
}

func newMockEnforcer() *mockEnforcer {
	return &mockEnforcer{allowed: make(map[string]bool)}
}

func (m *mockEnforcer) Allow(sub, obj, act string) {
	m.allowed[fmt.Sprintf("%s|%s|%s", sub, obj, act)] = true
}

func (m *mockEnforcer) CheckPermission(sub, obj, act string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return m.allowed[fmt.Sprintf("%s|%s|%s", sub, obj, act)], nil
}

// --- RequirePermission tests ---

func TestRequirePermission_Allowed(t *testing.T) {
	enforcer := newMockEnforcer()
	enforcer.Allow("user-1", "/tokens", "read")

	pm := middleware.NewPermissionMiddleware(enforcer)

	r := gin.New()
	r.Use(injectClaims(&domain.TokenClaims{Subject: "user-1"}))
	r.GET("/tokens", pm.RequirePermission("/tokens", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", http.NoBody))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequirePermission_Denied(t *testing.T) {
	enforcer := newMockEnforcer()
	// No policy added — everything is denied by default.

	pm := middleware.NewPermissionMiddleware(enforcer)

	r := gin.New()
	r.Use(injectClaims(&domain.TokenClaims{Subject: "user-1"}))
	r.GET("/tokens", pm.RequirePermission("/tokens", "write"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", http.NoBody))
	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestRequirePermission_NoClaims_Returns401(t *testing.T) {
	enforcer := newMockEnforcer()
	pm := middleware.NewPermissionMiddleware(enforcer)

	// No injectClaims middleware — simulates unauthenticated request.
	r := gin.New()
	r.GET("/tokens", pm.RequirePermission("/tokens", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", http.NoBody))
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestRequirePermission_EnforcerError_Returns500(t *testing.T) {
	enforcer := newMockEnforcer()
	enforcer.err = fmt.Errorf("database connection lost")

	pm := middleware.NewPermissionMiddleware(enforcer)

	r := gin.New()
	r.Use(injectClaims(&domain.TokenClaims{Subject: "user-1"}))
	r.GET("/tokens", pm.RequirePermission("/tokens", "read"), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tokens", http.NoBody))
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRequirePermission_SubjectIsTakenFromClaims(t *testing.T) {
	enforcer := newMockEnforcer()
	enforcer.Allow("correct-subject", "/resource", "delete")

	pm := middleware.NewPermissionMiddleware(enforcer)

	tests := []struct {
		name       string
		subject    string
		wantStatus int
	}{
		{
			name:       "correct subject is allowed",
			subject:    "correct-subject",
			wantStatus: http.StatusOK,
		},
		{
			name:       "different subject is denied",
			subject:    "other-subject",
			wantStatus: http.StatusForbidden,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(injectClaims(&domain.TokenClaims{Subject: tc.subject}))
			r.DELETE("/resource", pm.RequirePermission("/resource", "delete"), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/resource", http.NoBody))
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// TestRequirePermission_PipelineWithAuthMiddleware is a full pipeline integration
// test that chains AuthMiddleware → RequirePermission. It verifies that the
// subject extracted by AuthMiddleware flows correctly into the permission check.
func TestRequirePermission_PipelineWithAuthMiddleware(t *testing.T) {
	enforcer := newMockEnforcer()
	enforcer.Allow("admin-user", "/admin/users", "list")

	pm := middleware.NewPermissionMiddleware(enforcer)

	claims := &domain.TokenClaims{
		Subject:    "admin-user",
		Roles:      []string{"admin"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-admin-1",
	}
	v := &mockValidator{claims: claims}

	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.GET("/admin/users",
		pm.RequirePermission("/admin/users", "list"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_tok")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestRequirePermission_PipelineWithAuthMiddleware_Denied verifies the full
// pipeline rejects a subject without the required policy.
func TestRequirePermission_PipelineWithAuthMiddleware_Denied(t *testing.T) {
	enforcer := newMockEnforcer()
	// No policies — all requests will be denied.

	pm := middleware.NewPermissionMiddleware(enforcer)

	claims := &domain.TokenClaims{
		Subject:    "regular-user",
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-user-1",
	}
	v := &mockValidator{claims: claims}

	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.GET("/admin/users",
		pm.RequirePermission("/admin/users", "list"),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/users", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_tok")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
