package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/middleware"
)

const (
	adminTokenA = "test-not-a-real-admin-token-aaaaaaaaa"
	adminTokenB = "test-not-a-real-admin-token-bbbbbbbbb"
)

func adminTokenRouter(tokens []string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.AdminToken(tokens))
	r.GET("/x", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func TestAdminToken(t *testing.T) {
	tests := []struct {
		name       string
		tokens     []string
		authz      string
		wantStatus int
		wantCode   string
	}{
		{"no header", []string{adminTokenA}, "", http.StatusUnauthorized, "UNAUTHORIZED"},
		{"not bearer", []string{adminTokenA}, adminTokenA, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"wrong token", []string{adminTokenA}, "Bearer " + adminTokenB, http.StatusUnauthorized, "UNAUTHORIZED"},
		{"longer than token", []string{adminTokenA}, "Bearer " + adminTokenA + "x", http.StatusUnauthorized, "UNAUTHORIZED"},
		{"valid single", []string{adminTokenA}, "Bearer " + adminTokenA, http.StatusOK, ""},
		{"valid first of two", []string{adminTokenA, adminTokenB}, "Bearer " + adminTokenA, http.StatusOK, ""},
		{"valid second of two", []string{adminTokenA, adminTokenB}, "Bearer " + adminTokenB, http.StatusOK, ""},
		{"none configured, no header", nil, "", http.StatusServiceUnavailable, "admin_api_disabled"},
		{"none configured, any token", nil, "Bearer " + adminTokenA, http.StatusServiceUnavailable, "admin_api_disabled"},
		{"empty strings ignored", []string{""}, "Bearer ", http.StatusServiceUnavailable, "admin_api_disabled"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/x", http.NoBody)
			if tc.authz != "" {
				req.Header.Set("Authorization", tc.authz)
			}
			w := httptest.NewRecorder()
			adminTokenRouter(tc.tokens).ServeHTTP(w, req)

			require.Equal(t, tc.wantStatus, w.Code)
			if tc.wantCode != "" {
				assert.Contains(t, w.Body.String(), `"code":"`+tc.wantCode+`"`)
			}
		})
	}
}
