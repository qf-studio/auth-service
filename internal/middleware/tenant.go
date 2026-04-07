package middleware

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

// Context keys for tenant resolution.
const (
	tenantIDContextKey     = "tenant_id"
	tenantConfigContextKey = "tenant_config"
	tenantHeader           = "X-Tenant-ID"
)

// TenantConfig holds per-tenant configuration stored alongside the tenant.
type TenantConfig struct {
	TenantID string
	Name     string
	Active   bool
}

// TenantResolver looks up a tenant by its identifier (slug or ID).
type TenantResolver interface {
	ResolveTenant(ctx context.Context, identifier string) (*TenantConfig, error)
}

// TenantCache caches resolved tenant configs to avoid repeated DB lookups.
type TenantCache struct {
	mu      sync.RWMutex
	entries map[string]tenantCacheEntry
	ttl     time.Duration
}

type tenantCacheEntry struct {
	config    *TenantConfig
	expiresAt time.Time
}

// NewTenantCache creates a new in-memory tenant cache with the given TTL.
func NewTenantCache(ttl time.Duration) *TenantCache {
	return &TenantCache{
		entries: make(map[string]tenantCacheEntry),
		ttl:     ttl,
	}
}

// Get retrieves a cached tenant config. Returns nil if not found or expired.
func (tc *TenantCache) Get(identifier string) *TenantConfig {
	tc.mu.RLock()
	defer tc.mu.RUnlock()

	entry, ok := tc.entries[identifier]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.config
}

// Set stores a tenant config in the cache.
func (tc *TenantCache) Set(identifier string, cfg *TenantConfig) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	tc.entries[identifier] = tenantCacheEntry{
		config:    cfg,
		expiresAt: time.Now().Add(tc.ttl),
	}
}

// Invalidate removes a specific entry from the cache.
func (tc *TenantCache) Invalidate(identifier string) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	delete(tc.entries, identifier)
}

// TenantMiddleware returns a Gin middleware that resolves the current tenant from
// the request subdomain or X-Tenant-ID header (based on config.ResolutionMode),
// validates the tenant is active, and stores the tenant ID and config in the context.
func TenantMiddleware(cfg config.TenantConfig, resolver TenantResolver, cache *TenantCache) gin.HandlerFunc {
	return func(c *gin.Context) {
		identifier := resolveTenantIdentifier(c, cfg)

		if identifier == "" {
			if cfg.DefaultID != "" {
				identifier = cfg.DefaultID
			} else {
				domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest,
					"tenant identifier required")
				return
			}
		}

		// Check cache first.
		if cached := cache.Get(identifier); cached != nil {
			if !cached.Active {
				domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden,
					"tenant is inactive")
				return
			}
			c.Set(tenantIDContextKey, cached.TenantID)
			c.Set(tenantConfigContextKey, cached)
			injectTenantContext(c, cached.TenantID)
			c.Next()
			return
		}

		// Cache miss — resolve from backing store.
		tenantCfg, err := resolver.ResolveTenant(c.Request.Context(), identifier)
		if err != nil {
			domain.RespondWithError(c, http.StatusNotFound, domain.CodeNotFound,
				"tenant not found")
			return
		}

		cache.Set(identifier, tenantCfg)

		if !tenantCfg.Active {
			domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden,
				"tenant is inactive")
			return
		}

		c.Set(tenantIDContextKey, tenantCfg.TenantID)
		c.Set(tenantConfigContextKey, tenantCfg)
		injectTenantContext(c, tenantCfg.TenantID)
		c.Next()
	}
}

// resolveTenantIdentifier extracts the tenant identifier from the request
// based on the configured resolution mode.
func resolveTenantIdentifier(c *gin.Context, cfg config.TenantConfig) string {
	switch cfg.ResolutionMode {
	case "subdomain":
		return extractSubdomain(c.Request.Host, cfg.BaseDomain)
	case "header":
		return c.GetHeader(tenantHeader)
	default: // "both" — subdomain takes priority, then header
		if sub := extractSubdomain(c.Request.Host, cfg.BaseDomain); sub != "" {
			return sub
		}
		return c.GetHeader(tenantHeader)
	}
}

// extractSubdomain extracts the tenant slug from the request host.
// For host "acme.auth.quantflow.studio" with baseDomain "auth.quantflow.studio",
// it returns "acme". Returns empty string if the host doesn't match.
func extractSubdomain(host, baseDomain string) string {
	if baseDomain == "" {
		return ""
	}

	// Strip port if present.
	if idx := strings.LastIndex(host, ":"); idx != -1 {
		host = host[:idx]
	}

	host = strings.ToLower(host)
	baseDomain = strings.ToLower(baseDomain)

	suffix := "." + baseDomain
	if !strings.HasSuffix(host, suffix) {
		return ""
	}

	sub := strings.TrimSuffix(host, suffix)
	// Must be a single label (no dots — e.g. "acme", not "a.b").
	if sub == "" || strings.Contains(sub, ".") {
		return ""
	}
	return sub
}

// injectTenantContext stores the tenant ID in the request's standard context.Context
// so that downstream services accessing c.Request.Context() can retrieve it via
// domain.TenantIDFromContext.
func injectTenantContext(c *gin.Context, tenantID string) {
	parsed, err := uuid.Parse(tenantID)
	if err != nil {
		return
	}
	c.Request = c.Request.WithContext(domain.WithTenantID(c.Request.Context(), parsed))
}

// TenantIDFromContext retrieves the resolved tenant ID from the Gin context.
// Returns empty string if no tenant was resolved.
func TenantIDFromContext(c *gin.Context) string {
	return c.GetString(tenantIDContextKey)
}

// TenantConfigFromContext retrieves the resolved tenant config from the Gin context.
// Returns nil if no tenant was resolved.
func TenantConfigFromContext(c *gin.Context) *TenantConfig {
	if v, exists := c.Get(tenantConfigContextKey); exists {
		if tc, ok := v.(*TenantConfig); ok {
			return tc
		}
	}
	return nil
}
