package metrics

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	c := New()
	assert.NotNil(t, c)
	assert.Equal(t, len(defaultBuckets), len(c.buckets))
}

func TestNewWithBuckets(t *testing.T) {
	buckets := []float64{1, 0.5, 0.1}
	c := NewWithBuckets(buckets)
	// Should be sorted.
	assert.Equal(t, []float64{0.1, 0.5, 1}, c.buckets)
}

func TestRecordRequest_IncrementsTotalAndStatusCode(t *testing.T) {
	c := New()

	c.RecordRequest(200, 10*time.Millisecond, "GET", "/api/v1/health")
	c.RecordRequest(200, 20*time.Millisecond, "GET", "/api/v1/health")
	c.RecordRequest(404, 5*time.Millisecond, "GET", "/api/v1/users")

	assert.Equal(t, int64(3), c.totalRequests.Load())

	c.statusMu.RLock()
	assert.Equal(t, int64(2), c.statusCounts[200])
	assert.Equal(t, int64(1), c.statusCounts[404])
	c.statusMu.RUnlock()
}

func TestRecordRequest_TracksEndpoints(t *testing.T) {
	c := New()
	c.RecordRequest(200, time.Millisecond, "GET", "/health")
	c.RecordRequest(201, time.Millisecond, "POST", "/users")
	c.RecordRequest(200, time.Millisecond, "GET", "/health")

	c.endpointMu.RLock()
	assert.Equal(t, int64(2), c.endpointCounts["GET /health"])
	assert.Equal(t, int64(1), c.endpointCounts["POST /users"])
	c.endpointMu.RUnlock()
}

func TestRecordDuration_HistogramBuckets(t *testing.T) {
	// Use simple buckets for clarity: 0.01s, 0.1s, 1s
	c := NewWithBuckets([]float64{0.01, 0.1, 1})

	c.RecordRequest(200, 5*time.Millisecond, "GET", "/a")   // <= 0.01
	c.RecordRequest(200, 50*time.Millisecond, "GET", "/b")  // <= 0.1
	c.RecordRequest(200, 500*time.Millisecond, "GET", "/c") // <= 1
	c.RecordRequest(200, 5*time.Second, "GET", "/d")        // +Inf

	assert.Equal(t, int64(1), c.bucketCounts[0].Load()) // <= 0.01
	assert.Equal(t, int64(1), c.bucketCounts[1].Load()) // <= 0.1
	assert.Equal(t, int64(1), c.bucketCounts[2].Load()) // <= 1
	assert.Equal(t, int64(1), c.bucketCounts[3].Load()) // +Inf

	assert.Equal(t, int64(4), c.durationNum.Load())
	assert.Greater(t, c.durationSum.Load(), int64(0))
}

func TestRecordAuthEvent(t *testing.T) {
	c := New()

	c.RecordAuthEvent("login_attempts_total", "success")
	c.RecordAuthEvent("login_attempts_total", "success")
	c.RecordAuthEvent("login_attempts_total", "failure")
	c.RecordAuthEvent("token_generations_total", "success")

	c.authMu.RLock()
	defer c.authMu.RUnlock()

	assert.Equal(t, int64(2), c.authEvents["login_attempts_total:success"])
	assert.Equal(t, int64(1), c.authEvents["login_attempts_total:failure"])
	assert.Equal(t, int64(1), c.authEvents["token_generations_total:success"])
}

func TestConcurrentSafety(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	n := 100

	wg.Add(n * 3)
	for i := 0; i < n; i++ {
		go func() {
			defer wg.Done()
			c.RecordRequest(200, time.Millisecond, "GET", "/test")
		}()
		go func() {
			defer wg.Done()
			c.RecordAuthEvent("login_attempts_total", "success")
		}()
		go func() {
			defer wg.Done()
			_ = c.PrometheusExport()
		}()
	}
	wg.Wait()

	assert.Equal(t, int64(n), c.totalRequests.Load())
}

func TestJSONExport(t *testing.T) {
	c := NewWithBuckets([]float64{0.01, 0.1, 1})

	c.RecordRequest(200, 5*time.Millisecond, "GET", "/health")
	c.RecordRequest(500, 50*time.Millisecond, "POST", "/login")
	c.RecordAuthEvent("login_attempts_total", "success")
	c.RecordAuthEvent("token_validations_total", "failure")

	result := c.JSONExport()

	// Verify it serializes cleanly to JSON.
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var snap JSONSnapshot
	require.NoError(t, json.Unmarshal(data, &snap))

	assert.Equal(t, int64(2), snap.TotalRequests)
	assert.Equal(t, int64(1), snap.StatusCodes["200"])
	assert.Equal(t, int64(1), snap.StatusCodes["500"])
	assert.Equal(t, int64(1), snap.Endpoints["GET /health"])
	assert.Equal(t, int64(1), snap.Endpoints["POST /login"])
	assert.Equal(t, int64(2), snap.Duration.Count)
	assert.Greater(t, snap.Duration.SumMs, float64(0))
	assert.Equal(t, int64(1), snap.AuthEvents["login_attempts_total:success"])
	assert.Equal(t, int64(1), snap.AuthEvents["token_validations_total:failure"])

	// Histogram buckets should be cumulative.
	lastCount := int64(0)
	for _, b := range snap.Duration.Buckets {
		assert.GreaterOrEqual(t, b.Count, lastCount)
		lastCount = b.Count
	}
	// Last bucket (+Inf) should equal total count.
	assert.Equal(t, int64(2), snap.Duration.Buckets[len(snap.Duration.Buckets)-1].Count)
}

func TestPrometheusExport(t *testing.T) {
	c := NewWithBuckets([]float64{0.01, 0.1, 1})

	c.RecordRequest(200, 5*time.Millisecond, "GET", "/health")
	c.RecordAuthEvent("login_attempts_total", "success")

	output := c.PrometheusExport()

	assert.Contains(t, output, "http_requests_total 1")
	assert.Contains(t, output, `http_requests_by_status{code="200"} 1`)
	assert.Contains(t, output, `http_request_duration_seconds_bucket{le="0.010"}`)
	assert.Contains(t, output, `http_request_duration_seconds_bucket{le="+Inf"} 1`)
	assert.Contains(t, output, "http_request_duration_seconds_sum")
	assert.Contains(t, output, "http_request_duration_seconds_count 1")
	assert.Contains(t, output, `auth_events_total{event="login_attempts_total",outcome="success"} 1`)

	// Verify TYPE and HELP annotations present.
	assert.Contains(t, output, "# TYPE http_requests_total counter")
	assert.Contains(t, output, "# HELP http_requests_total")
	assert.Contains(t, output, "# TYPE http_request_duration_seconds histogram")
}

func TestPrometheusExport_NoAuthEvents(t *testing.T) {
	c := New()
	c.RecordRequest(200, time.Millisecond, "GET", "/test")
	output := c.PrometheusExport()

	assert.Contains(t, output, "http_requests_total 1")
	assert.NotContains(t, output, "auth_events_total")
}

func TestMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c := New()

	router := gin.New()
	router.Use(c.Middleware())
	router.GET("/test", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, int64(1), c.totalRequests.Load())

	c.statusMu.RLock()
	assert.Equal(t, int64(1), c.statusCounts[200])
	c.statusMu.RUnlock()

	c.endpointMu.RLock()
	assert.Equal(t, int64(1), c.endpointCounts["GET /test"])
	c.endpointMu.RUnlock()

	assert.Greater(t, c.durationNum.Load(), int64(0))
}

func TestMiddleware_MultipleStatuses(t *testing.T) {
	gin.SetMode(gin.TestMode)
	c := New()

	router := gin.New()
	router.Use(c.Middleware())
	router.GET("/ok", func(ctx *gin.Context) {
		ctx.String(http.StatusOK, "ok")
	})
	router.GET("/notfound", func(ctx *gin.Context) {
		ctx.String(http.StatusNotFound, "not found")
	})

	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/ok", nil)
		router.ServeHTTP(w, req)
	}
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/notfound", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, int64(4), c.totalRequests.Load())

	c.statusMu.RLock()
	assert.Equal(t, int64(3), c.statusCounts[200])
	assert.Equal(t, int64(1), c.statusCounts[404])
	c.statusMu.RUnlock()
}

func TestJSONExport_EmptyCollector(t *testing.T) {
	c := New()
	result := c.JSONExport()

	data, err := json.Marshal(result)
	require.NoError(t, err)

	var snap JSONSnapshot
	require.NoError(t, json.Unmarshal(data, &snap))

	assert.Equal(t, int64(0), snap.TotalRequests)
	assert.Empty(t, snap.StatusCodes)
	assert.Empty(t, snap.Endpoints)
	assert.Empty(t, snap.AuthEvents)
	assert.Equal(t, int64(0), snap.Duration.Count)

	// +Inf bucket should always be present.
	assert.NotEmpty(t, snap.Duration.Buckets)
	last := snap.Duration.Buckets[len(snap.Duration.Buckets)-1]
	assert.Equal(t, "+Inf", last.Le)
}

func TestPrometheusExport_CumulativeBuckets(t *testing.T) {
	c := NewWithBuckets([]float64{0.1, 1})

	// Both durations fall into the <=0.1 bucket.
	c.RecordRequest(200, 10*time.Millisecond, "GET", "/a")
	c.RecordRequest(200, 50*time.Millisecond, "GET", "/b")

	output := c.PrometheusExport()

	// The <=0.1 bucket should show 2 (cumulative).
	assert.Contains(t, output, `http_request_duration_seconds_bucket{le="0.100"} 2`)
	// The <=1 bucket should also show 2 (cumulative).
	assert.Contains(t, output, `http_request_duration_seconds_bucket{le="1.000"} 2`)
	assert.Contains(t, output, `http_request_duration_seconds_bucket{le="+Inf"} 2`)
}

func TestPrometheusExport_SortedOutput(t *testing.T) {
	c := New()
	c.RecordRequest(500, time.Millisecond, "GET", "/a")
	c.RecordRequest(200, time.Millisecond, "GET", "/b")
	c.RecordRequest(404, time.Millisecond, "GET", "/c")

	output := c.PrometheusExport()

	// Status codes should appear in ascending order.
	idx200 := strings.Index(output, `code="200"`)
	idx404 := strings.Index(output, `code="404"`)
	idx500 := strings.Index(output, `code="500"`)

	assert.Greater(t, idx404, idx200)
	assert.Greater(t, idx500, idx404)
}
