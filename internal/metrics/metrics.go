// Package metrics provides request and auth-event metrics collection with
// Prometheus text exposition and JSON export support.
package metrics

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
)

// Default histogram bucket boundaries (in seconds) for response durations.
var defaultBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}

// Collector gathers HTTP request metrics and auth-specific counters.
// All operations are safe for concurrent use.
type Collector struct {
	totalRequests atomic.Int64

	// status code breakdown
	statusMu     sync.RWMutex
	statusCounts map[int]int64

	// response duration histogram
	buckets      []float64
	bucketCounts []atomic.Int64 // len == len(buckets)+1 (+Inf bucket)
	durationSum  atomic.Int64   // nanoseconds
	durationNum  atomic.Int64   // count of observations

	// auth-specific counters keyed by "eventType:outcome"
	authMu     sync.RWMutex
	authEvents map[string]int64

	// endpoint breakdown keyed by "METHOD /path"
	endpointMu     sync.RWMutex
	endpointCounts map[string]int64
}

// New creates a Collector with default histogram buckets.
func New() *Collector {
	return NewWithBuckets(defaultBuckets)
}

// NewWithBuckets creates a Collector with custom histogram bucket boundaries.
func NewWithBuckets(buckets []float64) *Collector {
	sorted := make([]float64, len(buckets))
	copy(sorted, buckets)
	sort.Float64s(sorted)

	return &Collector{
		statusCounts:   make(map[int]int64),
		buckets:        sorted,
		bucketCounts:   make([]atomic.Int64, len(sorted)+1),
		authEvents:     make(map[string]int64),
		endpointCounts: make(map[string]int64),
	}
}

// RecordRequest records a completed HTTP request.
func (c *Collector) RecordRequest(statusCode int, duration time.Duration, method, path string) {
	c.totalRequests.Add(1)

	c.statusMu.Lock()
	c.statusCounts[statusCode]++
	c.statusMu.Unlock()

	c.recordDuration(duration)

	endpoint := method + " " + path
	c.endpointMu.Lock()
	c.endpointCounts[endpoint]++
	c.endpointMu.Unlock()
}

// RecordGRPCRequest records a completed gRPC request. The method is the full
// gRPC method name (e.g. "/auth.v1.AuthService/ValidateToken") and code is
// the gRPC status code string (e.g. "OK").
func (c *Collector) RecordGRPCRequest(method, code string, duration time.Duration) {
	c.totalRequests.Add(1)
	c.recordDuration(duration)

	endpoint := "gRPC " + method + " " + code
	c.endpointMu.Lock()
	c.endpointCounts[endpoint]++
	c.endpointMu.Unlock()
}

// recordDuration places the observation into the correct histogram bucket.
func (c *Collector) recordDuration(d time.Duration) {
	sec := d.Seconds()
	c.durationSum.Add(int64(d))
	c.durationNum.Add(1)

	for i, b := range c.buckets {
		if sec <= b {
			c.bucketCounts[i].Add(1)
			return
		}
	}
	// +Inf bucket
	c.bucketCounts[len(c.buckets)].Add(1)
}

// RecordAuthEvent increments the counter for the given auth event type and
// outcome (e.g., eventType="login_attempts_total", outcome="success").
func (c *Collector) RecordAuthEvent(eventType, outcome string) {
	key := eventType + ":" + outcome
	c.authMu.Lock()
	c.authEvents[key]++
	c.authMu.Unlock()
}

// Middleware returns a Gin middleware that records request duration, status
// code, and endpoint for every request processed.
func (c *Collector) Middleware() gin.HandlerFunc {
	return func(ctx *gin.Context) {
		start := time.Now()
		ctx.Next()
		c.RecordRequest(ctx.Writer.Status(), time.Since(start), ctx.Request.Method, ctx.FullPath())
	}
}

// --- Export types ----------------------------------------------------------

// JSONSnapshot is the structure returned by JSONExport.
type JSONSnapshot struct {
	TotalRequests int64            `json:"total_requests"`
	StatusCodes   map[string]int64 `json:"status_codes"`
	Endpoints     map[string]int64 `json:"endpoints"`
	Duration      DurationSnapshot `json:"duration"`
	AuthEvents    map[string]int64 `json:"auth_events"`
}

// DurationSnapshot holds histogram data for JSON export.
type DurationSnapshot struct {
	Count   int64            `json:"count"`
	SumMs   float64          `json:"sum_ms"`
	Buckets []BucketSnapshot `json:"buckets"`
}

// BucketSnapshot represents one histogram bucket boundary and its cumulative count.
type BucketSnapshot struct {
	Le    string `json:"le"`
	Count int64  `json:"count"`
}

// JSONExport returns a snapshot of all metrics suitable for JSON marshalling.
func (c *Collector) JSONExport() interface{} {
	snap := JSONSnapshot{
		TotalRequests: c.totalRequests.Load(),
		StatusCodes:   make(map[string]int64),
		Endpoints:     make(map[string]int64),
		AuthEvents:    make(map[string]int64),
	}

	c.statusMu.RLock()
	for code, cnt := range c.statusCounts {
		snap.StatusCodes[fmt.Sprintf("%d", code)] = cnt
	}
	c.statusMu.RUnlock()

	c.endpointMu.RLock()
	for ep, cnt := range c.endpointCounts {
		snap.Endpoints[ep] = cnt
	}
	c.endpointMu.RUnlock()

	cumulative := int64(0)
	buckets := make([]BucketSnapshot, 0, len(c.buckets)+1)
	for i, b := range c.buckets {
		cumulative += c.bucketCounts[i].Load()
		buckets = append(buckets, BucketSnapshot{
			Le:    fmt.Sprintf("%.3f", b),
			Count: cumulative,
		})
	}
	cumulative += c.bucketCounts[len(c.buckets)].Load()
	buckets = append(buckets, BucketSnapshot{Le: "+Inf", Count: cumulative})

	snap.Duration = DurationSnapshot{
		Count:   c.durationNum.Load(),
		SumMs:   float64(c.durationSum.Load()) / float64(time.Millisecond),
		Buckets: buckets,
	}

	c.authMu.RLock()
	for key, cnt := range c.authEvents {
		snap.AuthEvents[key] = cnt
	}
	c.authMu.RUnlock()

	return snap
}

// PrometheusExport returns all metrics in Prometheus text exposition format.
func (c *Collector) PrometheusExport() string {
	var b strings.Builder

	total := c.totalRequests.Load()
	b.WriteString("# HELP http_requests_total Total number of HTTP requests.\n")
	b.WriteString("# TYPE http_requests_total counter\n")
	_, _ = fmt.Fprintf(&b, "http_requests_total %d\n\n", total)

	// Status codes
	c.statusMu.RLock()
	codes := make([]int, 0, len(c.statusCounts))
	for code := range c.statusCounts {
		codes = append(codes, code)
	}
	sort.Ints(codes)
	statusSnap := make(map[int]int64, len(c.statusCounts))
	for _, code := range codes {
		statusSnap[code] = c.statusCounts[code]
	}
	c.statusMu.RUnlock()

	b.WriteString("# HELP http_requests_by_status HTTP requests by status code.\n")
	b.WriteString("# TYPE http_requests_by_status counter\n")
	for _, code := range codes {
		_, _ = fmt.Fprintf(&b, "http_requests_by_status{code=\"%d\"} %d\n", code, statusSnap[code])
	}
	b.WriteString("\n")

	// Duration histogram
	b.WriteString("# HELP http_request_duration_seconds Duration of HTTP requests.\n")
	b.WriteString("# TYPE http_request_duration_seconds histogram\n")
	cumulative := int64(0)
	for i, bound := range c.buckets {
		cumulative += c.bucketCounts[i].Load()
		_, _ = fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=\"%.3f\"} %d\n", bound, cumulative)
	}
	cumulative += c.bucketCounts[len(c.buckets)].Load()
	_, _ = fmt.Fprintf(&b, "http_request_duration_seconds_bucket{le=\"+Inf\"} %d\n", cumulative)
	_, _ = fmt.Fprintf(&b, "http_request_duration_seconds_sum %.6f\n",
		float64(c.durationSum.Load())/float64(time.Second))
	_, _ = fmt.Fprintf(&b, "http_request_duration_seconds_count %d\n\n", c.durationNum.Load())

	// Auth events
	c.authMu.RLock()
	authKeys := make([]string, 0, len(c.authEvents))
	for k := range c.authEvents {
		authKeys = append(authKeys, k)
	}
	sort.Strings(authKeys)
	authSnap := make(map[string]int64, len(c.authEvents))
	for _, k := range authKeys {
		authSnap[k] = c.authEvents[k]
	}
	c.authMu.RUnlock()

	if len(authKeys) > 0 {
		b.WriteString("# HELP auth_events_total Auth event counters.\n")
		b.WriteString("# TYPE auth_events_total counter\n")
		for _, key := range authKeys {
			parts := strings.SplitN(key, ":", 2)
			eventType, outcome := parts[0], parts[1]
			_, _ = fmt.Fprintf(&b, "auth_events_total{event=\"%s\",outcome=\"%s\"} %d\n",
				eventType, outcome, authSnap[key])
		}
	}

	return b.String()
}
