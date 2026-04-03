package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// injectClaims returns a Gin middleware that directly sets claims in the
// context, bypassing token validation. Used to test RBAC middleware in
// isolation from AuthMiddleware.
func injectClaims(claims *domain.TokenClaims) gin.HandlerFunc {
	return func(c *gin.Context) {
		if claims != nil {
			c.Set("claims", claims)
			c.Set("user_id", claims.Subject)
		}
		c.Next()
	}
}

// --- GetClaims ---

func TestGetClaims_ReturnsClaims(t *testing.T) {
	claims := &domain.TokenClaims{Subject: "u1", Roles: []string{"user"}}

	var got *domain.TokenClaims
	r := gin.New()
	r.Use(injectClaims(claims))
	r.GET("/", func(c *gin.Context) {
		var err error
		got, err = middleware.GetClaims(c)
		require.NoError(t, err)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, got)
	assert.Equal(t, "u1", got.Subject)
}

func TestGetClaims_ErrorWhenAbsent(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		_, err := middleware.GetClaims(c)
		assert.ErrorIs(t, err, middleware.ErrNoClaims)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	assert.Equal(t, http.StatusOK, w.Code)
}

func TestGetClaims_ErrorOnWrongType(t *testing.T) {
	// Store a non-*domain.TokenClaims value under the claims key to hit the
	// type assertion failure branch.
	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("claims", "not-a-claims-struct")
		c.Next()
	})
	r.GET("/", func(c *gin.Context) {
		_, err := middleware.GetClaims(c)
		assert.ErrorIs(t, err, middleware.ErrNoClaims)
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	assert.Equal(t, http.StatusOK, w.Code)
}

// --- RequireRoles ---

func TestRequireRoles(t *testing.T) {
	tests := []struct {
		name       string
		claims     *domain.TokenClaims
		required   []string
		wantStatus int
	}{
		{
			name:       "user has the required role",
			claims:     &domain.TokenClaims{Roles: []string{"user"}},
			required:   []string{"user"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "user has one of multiple required roles (any-of)",
			claims:     &domain.TokenClaims{Roles: []string{"user", "moderator"}},
			required:   []string{"admin", "moderator"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "admin satisfies admin-only route",
			claims:     &domain.TokenClaims{Roles: []string{"admin"}},
			required:   []string{"admin"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "user lacks all required roles",
			claims:     &domain.TokenClaims{Roles: []string{"user"}},
			required:   []string{"admin"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "empty roles returns forbidden",
			claims:     &domain.TokenClaims{Roles: []string{}},
			required:   []string{"admin"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no claims returns 401",
			claims:     nil,
			required:   []string{"user"},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(injectClaims(tc.claims))
			r.GET("/route", middleware.RequireRoles(tc.required...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/route", http.NoBody))
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// --- RequireScopes ---

func TestRequireScopes(t *testing.T) {
	tests := []struct {
		name       string
		claims     *domain.TokenClaims
		required   []string
		wantStatus int
	}{
		{
			name:       "client has all required scopes",
			claims:     &domain.TokenClaims{Scopes: []string{"read:users", "write:tokens"}},
			required:   []string{"read:users", "write:tokens"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "client has superset of required scopes",
			claims:     &domain.TokenClaims{Scopes: []string{"read:users", "write:tokens", "admin:all"}},
			required:   []string{"read:users"},
			wantStatus: http.StatusOK,
		},
		{
			name:       "client missing one required scope",
			claims:     &domain.TokenClaims{Scopes: []string{"read:users"}},
			required:   []string{"read:users", "write:tokens"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "client has no scopes",
			claims:     &domain.TokenClaims{Scopes: []string{}},
			required:   []string{"read:users"},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no claims returns 401",
			claims:     nil,
			required:   []string{"read:users"},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(injectClaims(tc.claims))
			r.GET("/route", middleware.RequireScopes(tc.required...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/route", http.NoBody))
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// --- RequireClientType ---

func TestRequireClientType(t *testing.T) {
	tests := []struct {
		name       string
		claims     *domain.TokenClaims
		allowed    []string
		wantStatus int
	}{
		{
			name:       "user client type allowed",
			claims:     &domain.TokenClaims{ClientType: domain.ClientTypeUser},
			allowed:    []string{domain.ClientTypeUser},
			wantStatus: http.StatusOK,
		},
		{
			name:       "service client type allowed",
			claims:     &domain.TokenClaims{ClientType: domain.ClientTypeService},
			allowed:    []string{domain.ClientTypeService},
			wantStatus: http.StatusOK,
		},
		{
			name:       "agent client type allowed among multiple",
			claims:     &domain.TokenClaims{ClientType: domain.ClientTypeAgent},
			allowed:    []string{domain.ClientTypeService, domain.ClientTypeAgent},
			wantStatus: http.StatusOK,
		},
		{
			name:       "user type rejected from service-only route",
			claims:     &domain.TokenClaims{ClientType: domain.ClientTypeUser},
			allowed:    []string{domain.ClientTypeService},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "unknown client type rejected",
			claims:     &domain.TokenClaims{ClientType: "unknown"},
			allowed:    []string{domain.ClientTypeUser, domain.ClientTypeService, domain.ClientTypeAgent},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "no claims returns 401",
			claims:     nil,
			allowed:    []string{domain.ClientTypeUser},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := gin.New()
			r.Use(injectClaims(tc.claims))
			r.GET("/route", middleware.RequireClientType(tc.allowed...), func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/route", http.NoBody))
			assert.Equal(t, tc.wantStatus, w.Code)
		})
	}
}

// --- Chained middleware integration ---

func TestChainedAuthAndRBAC(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:    "admin-user",
		Roles:      []string{"admin"},
		Scopes:     []string{"admin:all"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-1",
	}
	v := &mockValidator{claims: claims}

	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.GET("/admin",
		middleware.RequireRoles("admin"),
		middleware.RequireScopes("admin:all"),
		middleware.RequireClientType(domain.ClientTypeUser),
		func(c *gin.Context) {
			c.Status(http.StatusOK)
		},
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_tok")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
