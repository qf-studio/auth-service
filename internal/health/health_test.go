package health

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockChecker is a configurable health checker for testing.
type mockChecker struct {
	name   string
	status Status
	err    error
	delay  time.Duration
}

func (m *mockChecker) Name() string { return m.name }

func (m *mockChecker) Check(_ context.Context) Result {
	if m.delay > 0 {
		time.Sleep(m.delay)
	}
	if m.err != nil {
		return Result{
			Status:  StatusUnhealthy,
			Message: m.err.Error(),
		}
	}
	return Result{Status: m.status}
}

func newMock(name string, status Status) *mockChecker {
	return &mockChecker{name: name, status: status}
}

func newFailingMock(name string, err error) *mockChecker {
	return &mockChecker{name: name, status: StatusUnhealthy, err: err}
}

// --- Service tests ---

func TestLiveness_AlwaysHealthy(t *testing.T) {
	svc := NewService(newFailingMock("db", errors.New("down")))
	resp := svc.Liveness()

	assert.Equal(t, StatusHealthy, resp.Status)
	assert.Empty(t, resp.Checks, "liveness must not run checkers")
	assert.GreaterOrEqual(t, resp.Uptime, time.Duration(0))
}

func TestHealth_NoCheckers(t *testing.T) {
	svc := NewService()
	resp := svc.Health(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
	assert.Empty(t, resp.Checks)
}

func TestHealth_AllHealthy(t *testing.T) {
	svc := NewService(
		newMock("postgres", StatusHealthy),
		newMock("redis", StatusHealthy),
	)
	resp := svc.Health(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
	require.Len(t, resp.Checks, 2)
	assert.Equal(t, StatusHealthy, resp.Checks["postgres"].Status)
	assert.Equal(t, StatusHealthy, resp.Checks["redis"].Status)
}

func TestHealth_AllUnhealthy(t *testing.T) {
	svc := NewService(
		newFailingMock("postgres", errors.New("connection refused")),
		newFailingMock("redis", errors.New("timeout")),
	)
	resp := svc.Health(context.Background())

	assert.Equal(t, StatusUnhealthy, resp.Status)
	require.Len(t, resp.Checks, 2)
	assert.Equal(t, StatusUnhealthy, resp.Checks["postgres"].Status)
	assert.Equal(t, "connection refused", resp.Checks["postgres"].Message)
	assert.Equal(t, StatusUnhealthy, resp.Checks["redis"].Status)
	assert.Equal(t, "timeout", resp.Checks["redis"].Message)
}

func TestHealth_Degraded(t *testing.T) {
	svc := NewService(
		newMock("postgres", StatusHealthy),
		newFailingMock("redis", errors.New("connection lost")),
	)
	resp := svc.Health(context.Background())

	assert.Equal(t, StatusDegraded, resp.Status)
	require.Len(t, resp.Checks, 2)
	assert.Equal(t, StatusHealthy, resp.Checks["postgres"].Status)
	assert.Equal(t, StatusUnhealthy, resp.Checks["redis"].Status)
}

func TestReadiness_HealthyWhenAllPass(t *testing.T) {
	svc := NewService(
		newMock("postgres", StatusHealthy),
		newMock("redis", StatusHealthy),
	)
	resp := svc.Readiness(context.Background())

	assert.Equal(t, StatusHealthy, resp.Status)
}

func TestReadiness_UnhealthyWhenDegraded(t *testing.T) {
	svc := NewService(
		newMock("postgres", StatusHealthy),
		newFailingMock("redis", errors.New("down")),
	)
	resp := svc.Readiness(context.Background())

	// Readiness is binary: degraded → unhealthy.
	assert.Equal(t, StatusUnhealthy, resp.Status)
}

func TestReadiness_UnhealthyWhenAllFail(t *testing.T) {
	svc := NewService(
		newFailingMock("postgres", errors.New("down")),
		newFailingMock("redis", errors.New("down")),
	)
	resp := svc.Readiness(context.Background())

	assert.Equal(t, StatusUnhealthy, resp.Status)
}

func TestHealth_RunsConcurrently(t *testing.T) {
	slow := &mockChecker{name: "slow", status: StatusHealthy, delay: 50 * time.Millisecond}
	fast := &mockChecker{name: "fast", status: StatusHealthy, delay: 50 * time.Millisecond}

	svc := NewService(slow, fast)
	start := time.Now()
	resp := svc.Health(context.Background())
	elapsed := time.Since(start)

	assert.Equal(t, StatusHealthy, resp.Status)
	// If run sequentially, would take ≥100ms. Concurrent should be ~50ms.
	assert.Less(t, elapsed, 90*time.Millisecond, "checks should run concurrently")
}

func TestHealth_UptimeIncreases(t *testing.T) {
	svc := NewService()
	resp1 := svc.Liveness()
	time.Sleep(5 * time.Millisecond)
	resp2 := svc.Liveness()

	assert.Greater(t, resp2.Uptime, resp1.Uptime)
}

// --- ToMarshalable tests ---

func TestResponse_ToMarshalable(t *testing.T) {
	resp := Response{
		Status: StatusDegraded,
		Checks: map[string]Result{
			"postgres": {Status: StatusHealthy, Duration: 1500 * time.Microsecond},
			"redis":    {Status: StatusUnhealthy, Message: "timeout", Duration: 5 * time.Millisecond},
		},
		Uptime: 2*time.Hour + 30*time.Minute,
	}

	m := resp.ToMarshalable()
	assert.Equal(t, "degraded", m.Status)
	assert.Equal(t, "2h30m0s", m.Uptime)
	require.Len(t, m.Checks, 2)
	assert.Equal(t, "healthy", m.Checks["postgres"].Status)
	assert.Equal(t, "unhealthy", m.Checks["redis"].Status)
	assert.Equal(t, "timeout", m.Checks["redis"].Message)
}

func TestResponse_ToMarshalable_NoChecks(t *testing.T) {
	resp := Response{
		Status: StatusHealthy,
		Uptime: time.Second,
	}
	m := resp.ToMarshalable()
	assert.Equal(t, "healthy", m.Status)
	assert.Nil(t, m.Checks)
}

// --- Status constants ---

func TestStatusConstants(t *testing.T) {
	assert.Equal(t, Status("healthy"), StatusHealthy)
	assert.Equal(t, Status("degraded"), StatusDegraded)
	assert.Equal(t, Status("unhealthy"), StatusUnhealthy)
}
