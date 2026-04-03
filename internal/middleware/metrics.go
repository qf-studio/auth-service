package middleware

import (
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

// MetricsCollector holds Prometheus metrics for the auth service.
type MetricsCollector struct {
	RequestDuration  *prometheus.HistogramVec
	RequestCounter   *prometheus.CounterVec
	LoginAttempts    prometheus.Counter
	TokenGenerations prometheus.Counter
	TokenValidations prometheus.Counter
}

// NewMetricsCollector creates and registers all Prometheus metrics on the given
// registerer. Pass prometheus.DefaultRegisterer for production use, or a custom
// registry for tests.
func NewMetricsCollector(reg prometheus.Registerer) *MetricsCollector {
	m := &MetricsCollector{
		RequestDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Duration of HTTP requests in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"status", "method", "path"}),

		RequestCounter: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total number of HTTP requests.",
		}, []string{"status", "method", "path"}),

		LoginAttempts: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "login_attempts_total",
			Help: "Total number of login attempts.",
		}),

		TokenGenerations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "token_generations_total",
			Help: "Total number of tokens generated.",
		}),

		TokenValidations: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "token_validations_total",
			Help: "Total number of token validations.",
		}),
	}

	reg.MustRegister(
		m.RequestDuration,
		m.RequestCounter,
		m.LoginAttempts,
		m.TokenGenerations,
		m.TokenValidations,
	)

	return m
}

// Middleware returns Gin middleware that records per-request duration and count.
func (m *MetricsCollector) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		status := strconv.Itoa(c.Writer.Status())
		method := c.Request.Method
		path := c.FullPath()
		if path == "" {
			path = "unmatched"
		}

		elapsed := time.Since(start).Seconds()
		m.RequestDuration.WithLabelValues(status, method, path).Observe(elapsed)
		m.RequestCounter.WithLabelValues(status, method, path).Inc()
	}
}
