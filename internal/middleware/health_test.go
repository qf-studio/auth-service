package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stubChecker implements HealthChecker for testing.
type stubChecker struct {
	name string
	err  error
}

func (s *stubChecker) Name() string                       { return s.name }
func (s *stubChecker) Check(_ context.Context) error      { return s.err }

func newHealthRouter(h *HealthHandler) *gin.Engine {
	r := gin.New()
	r.GET("/health", h.Health)
	r.GET("/liveness", h.Liveness)
	r.GET("/readiness", h.Readiness)
	return r
}

type healthResponse struct {
	Status string            `json:"status"`
	Checks map[string]string `json:"checks"`
	Uptime string            `json:"uptime"`
}

func doHealthRequest(t *testing.T, r *gin.Engine, path string) (*httptest.ResponseRecorder, healthResponse) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var resp healthResponse
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	return w, resp
}

func TestHealth(t *testing.T) {
	tests := []struct {
		name       string
		checkers   []HealthChecker
		wantStatus string
		wantCode   int
	}{
		{
			name: "all healthy",
			checkers: []HealthChecker{
				&stubChecker{name: "redis", err: nil},
				&stubChecker{name: "postgres", err: nil},
			},
			wantStatus: "healthy",
			wantCode:   http.StatusOK,
		},
		{
			name: "one unhealthy — degraded",
			checkers: []HealthChecker{
				&stubChecker{name: "redis", err: errors.New("connection refused")},
				&stubChecker{name: "postgres", err: nil},
			},
			wantStatus: "degraded",
			wantCode:   http.StatusServiceUnavailable,
		},
		{
			name: "all unhealthy",
			checkers: []HealthChecker{
				&stubChecker{name: "redis", err: errors.New("down")},
				&stubChecker{name: "postgres", err: errors.New("down")},
			},
			wantStatus: "unhealthy",
			wantCode:   http.StatusServiceUnavailable,
		},
		{
			name:       "no checkers — healthy",
			checkers:   nil,
			wantStatus: "healthy",
			wantCode:   http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHealthHandler(tt.checkers...)
			r := newHealthRouter(h)

			w, resp := doHealthRequest(t, r, "/health")
			assert.Equal(t, tt.wantCode, w.Code)
			assert.Equal(t, tt.wantStatus, resp.Status)
			assert.NotEmpty(t, resp.Uptime)

			for _, ch := range tt.checkers {
				expected := "healthy"
				if sc, ok := ch.(*stubChecker); ok && sc.err != nil {
					expected = "unhealthy"
				}
				assert.Equal(t, expected, resp.Checks[ch.Name()])
			}
		})
	}
}

func TestLiveness_AlwaysHealthy(t *testing.T) {
	h := NewHealthHandler(&stubChecker{name: "redis", err: errors.New("down")})
	r := newHealthRouter(h)

	w, resp := doHealthRequest(t, r, "/liveness")
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "healthy", resp.Status)
	assert.NotEmpty(t, resp.Uptime)
}

func TestReadiness(t *testing.T) {
	tests := []struct {
		name       string
		checkers   []HealthChecker
		wantStatus string
		wantCode   int
	}{
		{
			name: "ready when all healthy",
			checkers: []HealthChecker{
				&stubChecker{name: "redis", err: nil},
				&stubChecker{name: "postgres", err: nil},
			},
			wantStatus: "healthy",
			wantCode:   http.StatusOK,
		},
		{
			name: "not ready when degraded",
			checkers: []HealthChecker{
				&stubChecker{name: "redis", err: errors.New("timeout")},
				&stubChecker{name: "postgres", err: nil},
			},
			wantStatus: "degraded",
			wantCode:   http.StatusServiceUnavailable,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewHealthHandler(tt.checkers...)
			r := newHealthRouter(h)

			w, resp := doHealthRequest(t, r, "/readiness")
			assert.Equal(t, tt.wantCode, w.Code)
			assert.Equal(t, tt.wantStatus, resp.Status)
		})
	}
}
