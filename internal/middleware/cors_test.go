package middleware_test

import (
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

func defaultCORSConfig() config.CORSConfig {
	return config.CORSConfig{
		AllowedOrigins:   []string{"https://app.example.com", "https://admin.example.com"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type", "X-Request-ID"},
		ExposeHeaders:    []string{"X-Request-ID", "X-RateLimit-Remaining"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	}
}

func newCORSRouter(cfg config.CORSConfig) *gin.Engine {
	r := gin.New()
	r.Use(middleware.CORS(cfg))
	r.GET("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	r.POST("/test", func(c *gin.Context) { c.String(http.StatusOK, "ok") })
	return r
}

func TestCORS_AllowedOrigin(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Origin", "https://app.example.com")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
	assert.Equal(t, "Origin", w.Header().Get("Vary"))
}

func TestCORS_DisallowedOrigin(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Origin", "https://evil.example.com")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoOriginHeader(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	// No Origin header.
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_PreflightRequest(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodOptions, "/test", http.NoBody)
	req.Header.Set("Origin", "https://app.example.com")
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Equal(t, "https://app.example.com", w.Header().Get("Access-Control-Allow-Origin"))
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Methods"), "POST")
	assert.Contains(t, w.Header().Get("Access-Control-Allow-Headers"), "Authorization")
	assert.Equal(t, "86400", w.Header().Get("Access-Control-Max-Age"))
	assert.Equal(t, "true", w.Header().Get("Access-Control-Allow-Credentials"))
}

func TestCORS_ExposeHeaders(t *testing.T) {
	router := newCORSRouter(defaultCORSConfig())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Origin", "https://app.example.com")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-Request-ID")
	assert.Contains(t, w.Header().Get("Access-Control-Expose-Headers"), "X-RateLimit-Remaining")
}

func TestCORS_WildcardOrigin(t *testing.T) {
	cfg := config.CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET"},
		AllowedHeaders: []string{"Content-Type"},
		MaxAge:         1 * time.Hour,
	}
	router := newCORSRouter(cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Origin", "https://any-origin.com")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://any-origin.com", w.Header().Get("Access-Control-Allow-Origin"))
}

func TestCORS_NoCredentials(t *testing.T) {
	cfg := defaultCORSConfig()
	cfg.AllowCredentials = false
	router := newCORSRouter(cfg)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("Origin", "https://app.example.com")
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("Access-Control-Allow-Credentials"))
}
