// Package health provides health checking for service dependencies.
// It supports liveness, readiness, and detailed health reporting with
// degraded status when some (but not all) checks fail.
package health

import (
	"context"
	"sync"
	"time"
)

// Status represents the overall health status.
type Status string

const (
	StatusHealthy   Status = "healthy"
	StatusDegraded  Status = "degraded"
	StatusUnhealthy Status = "unhealthy"
)

// Result is the outcome of a single health check.
type Result struct {
	Status   Status        `json:"status"`
	Message  string        `json:"message,omitempty"`
	Duration time.Duration `json:"-"`
}

// Response is the full health check response returned to callers.
type Response struct {
	Status Status            `json:"status"`
	Checks map[string]Result `json:"checks,omitempty"`
	Uptime time.Duration     `json:"-"`
}

// MarshalableResponse is the JSON-friendly version of Response.
type MarshalableResponse struct {
	Status string                       `json:"status"`
	Checks map[string]MarshalableResult `json:"checks,omitempty"`
	Uptime string                       `json:"uptime"`
}

// MarshalableResult is the JSON-friendly version of Result.
type MarshalableResult struct {
	Status   string `json:"status"`
	Message  string `json:"message,omitempty"`
	Duration string `json:"duration"`
}

// ToMarshalable converts a Response to its JSON-friendly representation.
func (r Response) ToMarshalable() MarshalableResponse {
	m := MarshalableResponse{
		Status: string(r.Status),
		Uptime: r.Uptime.Round(time.Millisecond).String(),
	}
	if len(r.Checks) > 0 {
		m.Checks = make(map[string]MarshalableResult, len(r.Checks))
		for name, check := range r.Checks {
			m.Checks[name] = MarshalableResult{
				Status:   string(check.Status),
				Message:  check.Message,
				Duration: check.Duration.Round(time.Microsecond).String(),
			}
		}
	}
	return m
}

// Checker performs a named health check against a dependency.
type Checker interface {
	// Name returns a human-readable identifier for this checker.
	Name() string
	// Check runs the health check and returns the result.
	Check(ctx context.Context) Result
}

// Service aggregates multiple health checkers and computes overall status.
type Service struct {
	checkers []Checker
	start    time.Time
}

// NewService creates a health Service with the given checkers.
func NewService(checkers ...Checker) *Service {
	return &Service{
		checkers: checkers,
		start:    time.Now(),
	}
}

// Liveness returns a simple OK response. It does not check dependencies.
func (s *Service) Liveness() Response {
	return Response{
		Status: StatusHealthy,
		Uptime: time.Since(s.start),
	}
}

// Readiness checks all dependencies. All must pass for a healthy response.
func (s *Service) Readiness(ctx context.Context) Response {
	resp := s.Health(ctx)
	// Readiness is binary: anything other than healthy becomes unhealthy.
	if resp.Status != StatusHealthy {
		resp.Status = StatusUnhealthy
	}
	return resp
}

// Health runs all checkers concurrently and computes overall status.
// - All pass → healthy
// - Some pass → degraded
// - None pass → unhealthy
func (s *Service) Health(ctx context.Context) Response {
	if len(s.checkers) == 0 {
		return Response{
			Status: StatusHealthy,
			Uptime: time.Since(s.start),
		}
	}

	type namedResult struct {
		name   string
		result Result
	}

	results := make([]namedResult, len(s.checkers))
	var wg sync.WaitGroup
	wg.Add(len(s.checkers))

	for i, c := range s.checkers {
		go func(idx int, checker Checker) {
			defer wg.Done()
			results[idx] = namedResult{
				name:   checker.Name(),
				result: checker.Check(ctx),
			}
		}(i, c)
	}

	wg.Wait()

	checks := make(map[string]Result, len(results))
	var passed, failed int
	for _, nr := range results {
		checks[nr.name] = nr.result
		if nr.result.Status == StatusHealthy {
			passed++
		} else {
			failed++
		}
	}

	var status Status
	switch {
	case failed == 0:
		status = StatusHealthy
	case passed == 0:
		status = StatusUnhealthy
	default:
		status = StatusDegraded
	}

	return Response{
		Status: status,
		Checks: checks,
		Uptime: time.Since(s.start),
	}
}
