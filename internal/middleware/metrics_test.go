package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestMetrics(t *testing.T) (*MetricsCollector, *prometheus.Registry) {
	t.Helper()
	reg := prometheus.NewRegistry()
	m := NewMetricsCollector(reg)
	return m, reg
}

func TestMetricsMiddleware_IncrementsCounters(t *testing.T) {
	m, reg := newTestMetrics(t)

	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.POST("/test", func(c *gin.Context) { c.Status(http.StatusCreated) })

	tests := []struct {
		name   string
		method string
		path   string
		code   int
	}{
		{"GET 200", http.MethodGet, "/test", http.StatusOK},
		{"POST 201", http.MethodPost, "/test", http.StatusCreated},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)
			assert.Equal(t, tt.code, w.Code)
		})
	}

	// Gather and verify metrics.
	families, err := reg.Gather()
	require.NoError(t, err)

	familyMap := make(map[string]*dto.MetricFamily, len(families))
	for _, f := range families {
		familyMap[f.GetName()] = f
	}

	// Verify request counter.
	counterFamily, ok := familyMap["http_requests_total"]
	require.True(t, ok, "http_requests_total must be registered")
	assert.GreaterOrEqual(t, len(counterFamily.GetMetric()), 2, "should have at least 2 label combos")

	// Verify histogram exists.
	histFamily, ok := familyMap["http_request_duration_seconds"]
	require.True(t, ok, "http_request_duration_seconds must be registered")
	assert.NotEmpty(t, histFamily.GetMetric())
}

func TestMetricsMiddleware_RecordsStatusCode(t *testing.T) {
	m, reg := newTestMetrics(t)

	r := gin.New()
	r.Use(m.Middleware())
	r.GET("/ok", func(c *gin.Context) { c.Status(http.StatusOK) })
	r.GET("/fail", func(c *gin.Context) { c.Status(http.StatusInternalServerError) })

	// Fire one request per handler.
	for _, path := range []string{"/ok", "/fail"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
	}

	families, err := reg.Gather()
	require.NoError(t, err)

	for _, f := range families {
		if f.GetName() != "http_requests_total" {
			continue
		}
		statusCodes := map[string]bool{}
		for _, metric := range f.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "status" {
					statusCodes[lp.GetValue()] = true
				}
			}
		}
		assert.True(t, statusCodes["200"], "should record 200")
		assert.True(t, statusCodes["500"], "should record 500")
	}
}

func TestAuthSpecificCounters(t *testing.T) {
	m, reg := newTestMetrics(t)

	m.LoginAttempts.Inc()
	m.LoginAttempts.Inc()
	m.TokenGenerations.Inc()
	m.TokenValidations.Inc()
	m.TokenValidations.Inc()
	m.TokenValidations.Inc()

	families, err := reg.Gather()
	require.NoError(t, err)

	expected := map[string]float64{
		"login_attempts_total":    2,
		"token_generations_total": 1,
		"token_validations_total": 3,
	}

	for _, f := range families {
		if want, ok := expected[f.GetName()]; ok {
			require.Len(t, f.GetMetric(), 1)
			got := f.GetMetric()[0].GetCounter().GetValue()
			assert.Equal(t, want, got, "metric %s", f.GetName())
		}
	}
}
