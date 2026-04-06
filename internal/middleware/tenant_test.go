package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockTenantResolver implements middleware.TenantResolver for testing.
type mockTenantResolver struct {
	tenants map[string]*middleware.TenantConfig
	err     error
}

func (m *mockTenantResolver) ResolveTenant(_ context.Context, identifier string) (*middleware.TenantConfig, error) {
	if m.err != nil {
		return nil, m.err
	}
	tc, ok := m.tenants[identifier]
	if !ok {
		return nil, errors.New("tenant not found")
	}
	return tc, nil
}

func newTenantTestRouter(cfg config.TenantConfig, resolver middleware.TenantResolver, cache *middleware.TenantCache) *gin.Engine {
	r := gin.New()
	r.Use(middleware.TenantMiddleware(cfg, resolver, cache))
	r.GET("/resource", func(c *gin.Context) {
		tenantID := middleware.TenantIDFromContext(c)
		tc := middleware.TenantConfigFromContext(c)
		name := ""
		if tc != nil {
			name = tc.Name
		}
		c.String(http.StatusOK, tenantID+":"+name)
	})
	return r
}

func TestExtractSubdomain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tests := []struct {
		name       string
		host       string
		baseDomain string
		headerVal  string
		mode       string
		wantStatus int
		wantBody   string
	}{
		{
			name:       "subdomain resolution — valid subdomain",
			host:       "acme.auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
		{
			name:       "subdomain resolution — with port",
			host:       "acme.auth.quantflow.studio:4000",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
		{
			name:       "subdomain resolution — case insensitive",
			host:       "ACME.Auth.Quantflow.Studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
		{
			name:       "subdomain resolution — no match, no default",
			host:       "other.example.com",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "subdomain resolution — bare base domain, no default",
			host:       "auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "subdomain resolution — nested subdomain rejected",
			host:       "a.b.auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "subdomain",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "header resolution — valid header",
			host:       "auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "header",
			headerVal:  "acme",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
		{
			name:       "header resolution — missing header, no default",
			host:       "auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "header",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "both mode — subdomain takes priority over header",
			host:       "acme.auth.quantflow.studio",
			baseDomain: "auth.quantflow.studio",
			mode:       "both",
			headerVal:  "other-tenant",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
		{
			name:       "both mode — falls back to header when no subdomain",
			host:       "other.example.com",
			baseDomain: "auth.quantflow.studio",
			mode:       "both",
			headerVal:  "acme",
			wantStatus: http.StatusOK,
			wantBody:   "tenant-acme:Acme Corp",
		},
	}

	resolver := &mockTenantResolver{
		tenants: map[string]*middleware.TenantConfig{
			"acme": {TenantID: "tenant-acme", Name: "Acme Corp", Active: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cache := middleware.NewTenantCache(5 * time.Minute)
			cfg := config.TenantConfig{
				ResolutionMode: tt.mode,
				BaseDomain:     tt.baseDomain,
			}

			router := newTenantTestRouter(cfg, resolver, cache)
			req := httptest.NewRequest(http.MethodGet, "/resource", nil)
			req.Host = tt.host
			if tt.headerVal != "" {
				req.Header.Set("X-Tenant-ID", tt.headerVal)
			}
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			if tt.wantBody != "" {
				assert.Equal(t, tt.wantBody, w.Body.String())
			}
		})
	}
}

func TestTenantMiddleware_DefaultTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &mockTenantResolver{
		tenants: map[string]*middleware.TenantConfig{
			"default-id": {TenantID: "default-id", Name: "Default", Active: true},
		},
	}
	cache := middleware.NewTenantCache(5 * time.Minute)
	cfg := config.TenantConfig{
		ResolutionMode: "header",
		DefaultID:      "default-id",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-id:Default", w.Body.String())
}

func TestTenantMiddleware_InactiveTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &mockTenantResolver{
		tenants: map[string]*middleware.TenantConfig{
			"inactive": {TenantID: "inactive", Name: "Inactive Corp", Active: false},
		},
	}
	cache := middleware.NewTenantCache(5 * time.Minute)
	cfg := config.TenantConfig{
		ResolutionMode: "header",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Tenant-ID", "inactive")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTenantMiddleware_ResolverError(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &mockTenantResolver{err: errors.New("db error")}
	cache := middleware.NewTenantCache(5 * time.Minute)
	cfg := config.TenantConfig{
		ResolutionMode: "header",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Tenant-ID", "unknown")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestTenantCache(t *testing.T) {
	t.Run("get returns nil for missing key", func(t *testing.T) {
		cache := middleware.NewTenantCache(5 * time.Minute)
		assert.Nil(t, cache.Get("nonexistent"))
	})

	t.Run("set and get returns cached value", func(t *testing.T) {
		cache := middleware.NewTenantCache(5 * time.Minute)
		cfg := &middleware.TenantConfig{TenantID: "t1", Name: "Tenant 1", Active: true}
		cache.Set("t1", cfg)

		got := cache.Get("t1")
		require.NotNil(t, got)
		assert.Equal(t, "t1", got.TenantID)
		assert.Equal(t, "Tenant 1", got.Name)
	})

	t.Run("expired entry returns nil", func(t *testing.T) {
		cache := middleware.NewTenantCache(1 * time.Nanosecond)
		cfg := &middleware.TenantConfig{TenantID: "t1", Name: "Tenant 1", Active: true}
		cache.Set("t1", cfg)

		time.Sleep(2 * time.Millisecond)
		assert.Nil(t, cache.Get("t1"))
	})

	t.Run("invalidate removes entry", func(t *testing.T) {
		cache := middleware.NewTenantCache(5 * time.Minute)
		cfg := &middleware.TenantConfig{TenantID: "t1", Name: "Tenant 1", Active: true}
		cache.Set("t1", cfg)
		cache.Invalidate("t1")

		assert.Nil(t, cache.Get("t1"))
	})
}

func TestTenantMiddleware_CacheHit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Resolver that always errors — cache should prevent it from being called.
	resolver := &mockTenantResolver{err: errors.New("should not be called")}
	cache := middleware.NewTenantCache(5 * time.Minute)

	// Pre-populate cache.
	cache.Set("cached-tenant", &middleware.TenantConfig{
		TenantID: "cached-id",
		Name:     "Cached Tenant",
		Active:   true,
	})

	cfg := config.TenantConfig{
		ResolutionMode: "header",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Tenant-ID", "cached-tenant")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "cached-id:Cached Tenant", w.Body.String())
}

func TestTenantMiddleware_CacheHitInactive(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &mockTenantResolver{err: errors.New("should not be called")}
	cache := middleware.NewTenantCache(5 * time.Minute)

	cache.Set("inactive", &middleware.TenantConfig{
		TenantID: "inactive-id",
		Name:     "Inactive",
		Active:   false,
	})

	cfg := config.TenantConfig{
		ResolutionMode: "header",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Header.Set("X-Tenant-ID", "inactive")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

func TestTenantContextHelpers_NoTenant(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/test", func(c *gin.Context) {
		id := middleware.TenantIDFromContext(c)
		cfg := middleware.TenantConfigFromContext(c)
		assert.Equal(t, "", id)
		assert.Nil(t, cfg)
		c.String(http.StatusOK, "ok")
	})

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestTenantMiddleware_SubdomainWithEmptyBaseDomain(t *testing.T) {
	gin.SetMode(gin.TestMode)

	resolver := &mockTenantResolver{
		tenants: map[string]*middleware.TenantConfig{
			"default-id": {TenantID: "default-id", Name: "Default", Active: true},
		},
	}
	cache := middleware.NewTenantCache(5 * time.Minute)
	cfg := config.TenantConfig{
		ResolutionMode: "subdomain",
		BaseDomain:     "", // empty — subdomain extraction returns nothing
		DefaultID:      "default-id",
	}

	router := newTenantTestRouter(cfg, resolver, cache)
	req := httptest.NewRequest(http.MethodGet, "/resource", nil)
	req.Host = "anything.example.com"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Should fall through to default since subdomain extraction yields nothing.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "default-id:Default", w.Body.String())
}
