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

func TestSecurityHeaders_AllPresent(t *testing.T) {
	r := gin.New()
	r.Use(middleware.SecurityHeaders())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	tests := []struct {
		header   string
		expected string
	}{
		{"X-Content-Type-Options", "nosniff"},
		{"X-Frame-Options", "DENY"},
		{"X-XSS-Protection", "0"},
		{"Content-Security-Policy", "default-src 'none'"},
		{"Strict-Transport-Security", "max-age=31536000; includeSubDomains"},
		{"Referrer-Policy", "strict-origin-when-cross-origin"},
		{"Cache-Control", "no-store"},
		{"Permissions-Policy", ""},
	}

	for _, tc := range tests {
		t.Run(tc.header, func(t *testing.T) {
			got := w.Header().Get(tc.header)
			assert.Equal(t, tc.expected, got, "header %s", tc.header)
		})
	}
}

func TestSecurityHeaders_AppliedToEveryResponse(t *testing.T) {
	r := gin.New()
	r.Use(middleware.SecurityHeaders())
	r.GET("/ok", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.GET("/error", func(c *gin.Context) { c.String(http.StatusInternalServerError, "err") })

	for _, path := range []string{"/ok", "/error"} {
		t.Run(path, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, path, http.NoBody)
			r.ServeHTTP(w, req)

			// Security headers should be present regardless of status code.
			assert.Equal(t, "nosniff", w.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "DENY", w.Header().Get("X-Frame-Options"))
			assert.Equal(t, "no-store", w.Header().Get("Cache-Control"))
		})
	}
}
