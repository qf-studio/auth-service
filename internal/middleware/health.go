package middleware

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

// HealthChecker reports whether a single dependency is healthy.
type HealthChecker interface {
	// Name returns the dependency's identifier (e.g. "redis", "postgres").
	Name() string
	// Check returns nil when the dependency is reachable, or an error describing
	// the failure.
	Check(ctx context.Context) error
}

// RedisHealthChecker pings Redis to verify connectivity.
type RedisHealthChecker struct {
	client redis.Cmdable
}

// NewRedisHealthChecker creates a health checker that pings the given Redis client.
func NewRedisHealthChecker(client redis.Cmdable) *RedisHealthChecker {
	return &RedisHealthChecker{client: client}
}

func (r *RedisHealthChecker) Name() string { return "redis" }

func (r *RedisHealthChecker) Check(ctx context.Context) error {
	return r.client.Ping(ctx).Err()
}

// PostgresHealthChecker pings a database to verify connectivity.
// It accepts any type that implements Ping(context.Context) error.
type PostgresHealthChecker struct {
	pinger Pinger
}

// Pinger is satisfied by *pgxpool.Pool and similar database handles.
type Pinger interface {
	Ping(ctx context.Context) error
}

// NewPostgresHealthChecker creates a health checker that pings the database.
func NewPostgresHealthChecker(p Pinger) *PostgresHealthChecker {
	return &PostgresHealthChecker{pinger: p}
}

func (p *PostgresHealthChecker) Name() string { return "postgres" }

func (p *PostgresHealthChecker) Check(ctx context.Context) error {
	return p.pinger.Ping(ctx)
}

// HealthHandler provides Gin handlers for /health, /liveness, and /readiness.
type HealthHandler struct {
	checkers  []HealthChecker
	startTime time.Time
}

// NewHealthHandler creates a HealthHandler with the given dependency checkers.
func NewHealthHandler(checkers ...HealthChecker) *HealthHandler {
	return &HealthHandler{
		checkers:  checkers,
		startTime: time.Now(),
	}
}

// checkResult holds one checker's outcome.
type checkResult struct {
	name   string
	status string
	err    error
}

// runChecks runs all checkers concurrently with a 3-second timeout.
func (h *HealthHandler) runChecks(ctx context.Context) []checkResult {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	results := make([]checkResult, len(h.checkers))
	var wg sync.WaitGroup
	for i, ch := range h.checkers {
		wg.Add(1)
		go func(idx int, checker HealthChecker) {
			defer wg.Done()
			err := checker.Check(ctx)
			status := "healthy"
			if err != nil {
				status = "unhealthy"
			}
			results[idx] = checkResult{name: checker.Name(), status: status, err: err}
		}(i, ch)
	}
	wg.Wait()
	return results
}

// aggregateStatus determines the overall status from individual results.
func aggregateStatus(results []checkResult) string {
	unhealthy := 0
	for _, r := range results {
		if r.status == "unhealthy" {
			unhealthy++
		}
	}
	switch {
	case unhealthy == 0:
		return "healthy"
	case unhealthy < len(results):
		return "degraded"
	default:
		return "unhealthy"
	}
}

// statusCode maps a status string to an HTTP status code.
func statusCode(status string) int {
	if status == "healthy" {
		return http.StatusOK
	}
	return http.StatusServiceUnavailable
}

// Health is the aggregated health endpoint handler.
func (h *HealthHandler) Health(c *gin.Context) {
	results := h.runChecks(c.Request.Context())
	status := aggregateStatus(results)

	checks := make(map[string]string, len(results))
	for _, r := range results {
		checks[r.name] = r.status
	}

	c.JSON(statusCode(status), gin.H{
		"status": status,
		"checks": checks,
		"uptime": time.Since(h.startTime).String(),
	})
}

// Liveness returns 200 if the process is running — no dependency checks.
func (h *HealthHandler) Liveness(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status": "healthy",
		"uptime": time.Since(h.startTime).String(),
	})
}

// Readiness checks all dependencies and returns 200 only if all are healthy.
func (h *HealthHandler) Readiness(c *gin.Context) {
	results := h.runChecks(c.Request.Context())
	status := aggregateStatus(results)

	checks := make(map[string]string, len(results))
	for _, r := range results {
		checks[r.name] = r.status
	}

	c.JSON(statusCode(status), gin.H{
		"status": status,
		"checks": checks,
		"uptime": time.Since(h.startTime).String(),
	})
}
