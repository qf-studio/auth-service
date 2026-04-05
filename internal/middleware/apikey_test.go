package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockAPIKeyValidator implements middleware.APIKeyValidator for testing.
type mockAPIKeyValidator struct {
	info *middleware.APIKeyInfo
	err  error
}

func (m *mockAPIKeyValidator) ValidateAPIKey(_ context.Context, _ string) (*middleware.APIKeyInfo, error) {
	return m.info, m.err
}

func newAPIKeyTestRouter(v middleware.APIKeyValidator, rl *middleware.APIKeyRateLimiter) *gin.Engine {
	r := gin.New()
	r.Use(middleware.APIKeyMiddleware(v, rl))
	r.GET("/resource", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.String(http.StatusOK, userID)
	})
	return r
}

func TestAPIKeyMiddleware_NoHeader_FallsThrough(t *testing.T) {
	v := &mockAPIKeyValidator{info: &middleware.APIKeyInfo{ClientID: "c1"}}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	router.ServeHTTP(w, req)

	// No X-API-Key → middleware falls through, handler runs with empty user_id.
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Body.String())
}

func TestAPIKeyMiddleware_ValidKey_SetsClaims(t *testing.T) {
	info := &middleware.APIKeyInfo{
		ClientID:   "client-abc",
		ClientType: domain.ClientTypeService,
		Scopes:     []string{"read:data", "write:data"},
		RateLimit:  0,
	}
	v := &mockAPIKeyValidator{info: info}
	rl := middleware.NewAPIKeyRateLimiter()

	var capturedClaims *domain.TokenClaims
	r := gin.New()
	r.Use(middleware.APIKeyMiddleware(v, rl))
	r.GET("/check", func(c *gin.Context) {
		got, err := middleware.GetClaims(c)
		require.NoError(t, err)
		capturedClaims = got
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_testkey123")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedClaims)
	assert.Equal(t, "client-abc", capturedClaims.Subject)
	assert.Equal(t, []string{"read:data", "write:data"}, capturedClaims.Scopes)
	assert.Equal(t, domain.ClientTypeService, capturedClaims.ClientType)
}

func TestAPIKeyMiddleware_ValidKey_SetsUserID(t *testing.T) {
	info := &middleware.APIKeyInfo{
		ClientID:   "client-xyz",
		ClientType: domain.ClientTypeAgent,
		Scopes:     []string{"read:metrics"},
	}
	v := &mockAPIKeyValidator{info: info}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_validkey")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "client-xyz", w.Body.String())
}

func TestAPIKeyMiddleware_InvalidKey_Returns401(t *testing.T) {
	v := &mockAPIKeyValidator{err: errors.New("key revoked")}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_badkey")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid or expired API key")
}

func TestAPIKeyMiddleware_RateLimitHeaders_Set(t *testing.T) {
	info := &middleware.APIKeyInfo{
		ClientID:   "client-rl",
		ClientType: domain.ClientTypeService,
		Scopes:     []string{"read:data"},
		RateLimit:  100,
	}
	v := &mockAPIKeyValidator{info: info}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_rlkey")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "100", w.Header().Get("X-RateLimit-Limit"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Remaining"))
	assert.NotEmpty(t, w.Header().Get("X-RateLimit-Reset"))
}

func TestAPIKeyMiddleware_NoRateLimit_NoHeaders(t *testing.T) {
	info := &middleware.APIKeyInfo{
		ClientID:   "client-nrl",
		ClientType: domain.ClientTypeService,
		Scopes:     []string{"read:data"},
		RateLimit:  0,
	}
	v := &mockAPIKeyValidator{info: info}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_nrlkey")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Empty(t, w.Header().Get("X-RateLimit-Limit"))
}

func TestAPIKeyMiddleware_RateLimitExceeded_Returns429(t *testing.T) {
	info := &middleware.APIKeyInfo{
		ClientID:   "client-burst",
		ClientType: domain.ClientTypeService,
		Scopes:     []string{"read:data"},
		RateLimit:  1, // 1 req/sec, burst 1
	}
	v := &mockAPIKeyValidator{info: info}
	rl := middleware.NewAPIKeyRateLimiter()

	router := newAPIKeyTestRouter(v, rl)

	// First request should succeed.
	w1 := httptest.NewRecorder()
	req1 := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req1.Header.Set("X-API-Key", "qf_ak_burstkey")
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Rapid second request should be rate-limited.
	w2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
	req2.Header.Set("X-API-Key", "qf_ak_burstkey")
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
	assert.Contains(t, w2.Body.String(), "rate limit exceeded")
	assert.NotEmpty(t, w2.Header().Get("Retry-After"))
	assert.Equal(t, "1", w2.Header().Get("X-RateLimit-Limit"))
	assert.Equal(t, "0", w2.Header().Get("X-RateLimit-Remaining"))
}

func TestAPIKeyMiddleware_TableDriven(t *testing.T) {
	validInfo := &middleware.APIKeyInfo{
		ClientID:   "client-td",
		ClientType: domain.ClientTypeService,
		Scopes:     []string{"read:data"},
	}

	tests := []struct {
		name             string
		apiKey           string
		validator        *mockAPIKeyValidator
		wantStatus       int
		wantBodyContains string
	}{
		{
			name:       "no API key header falls through",
			apiKey:     "",
			validator:  &mockAPIKeyValidator{info: validInfo},
			wantStatus: http.StatusOK,
		},
		{
			name:             "valid key authenticates",
			apiKey:           "qf_ak_valid",
			validator:        &mockAPIKeyValidator{info: validInfo},
			wantStatus:       http.StatusOK,
			wantBodyContains: "client-td",
		},
		{
			name:             "validation error returns 401",
			apiKey:           "qf_ak_bad",
			validator:        &mockAPIKeyValidator{err: errors.New("invalid key")},
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "invalid or expired API key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rl := middleware.NewAPIKeyRateLimiter()
			router := newAPIKeyTestRouter(tc.validator, rl)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/resource", http.NoBody)
			if tc.apiKey != "" {
				req.Header.Set("X-API-Key", tc.apiKey)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantBodyContains)
			}
		})
	}
}
