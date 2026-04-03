package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newRateLimitRouter(cfg config.RateLimitConfig) (*gin.Engine, *middleware.RateLimiter) {
	rl := middleware.NewRateLimiter(cfg)
	r := gin.New()
	r.Use(rl.Handler())
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r, rl
}

func TestRateLimit_AllowsRequestsUnderLimit(t *testing.T) {
	router, _ := newRateLimitRouter(config.RateLimitConfig{
		RPS:   10,
		Burst: 10,
	})

	for range 5 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	}
}

func TestRateLimit_RejectsWhenExhausted(t *testing.T) {
	// Burst of 2, very low RPS so tokens don't replenish during test.
	router, _ := newRateLimitRouter(config.RateLimitConfig{
		RPS:   1,
		Burst: 2,
	})

	// First 2 requests should succeed (burst).
	for i := range 2 {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
		router.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code, "request %d should succeed", i)
	}

	// Third request should be rate limited.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestRateLimit_SetsHeaders(t *testing.T) {
	router, _ := newRateLimitRouter(config.RateLimitConfig{
		RPS:   50,
		Burst: 100,
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

func TestRateLimit_RetryAfterOnExhaustion(t *testing.T) {
	router, _ := newRateLimitRouter(config.RateLimitConfig{
		RPS:   1,
		Burst: 1,
	})

	// Exhaust the bucket.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// Next request should get 429 with Retry-After.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
	assert.NotEmpty(t, w.Header().Get("Retry-After"))
}

func TestRateLimit_PerIPIsolation(t *testing.T) {
	router, rl := newRateLimitRouter(config.RateLimitConfig{
		RPS:   1,
		Burst: 1,
	})

	// IP 1: exhaust limit.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:1234"
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	// IP 1: should be rate limited.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.1:1234"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)

	// IP 2: should still have tokens.
	w = httptest.NewRecorder()
	req = httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.RemoteAddr = "10.0.0.2:1234"
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	// Both IPs should be tracked.
	assert.Equal(t, 2, rl.VisitorCount())
}

func TestFormatRateLimitHeaders(t *testing.T) {
	headers := middleware.FormatRateLimitHeaders(100, 95, 1700000000)
	assert.Equal(t, "100", headers["X-RateLimit-Limit"])
	assert.Equal(t, "95", headers["X-RateLimit-Remaining"])
	assert.Equal(t, "1700000000", headers["X-RateLimit-Reset"])
}
