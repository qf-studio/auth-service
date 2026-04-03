// Package middleware provides HTTP middleware for the auth service including
// rate limiting, security headers, CORS, and request size/timeout limits.
package middleware

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

// visitor tracks rate limit state for a single IP address.
type visitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter implements per-IP token bucket rate limiting.
type RateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*visitor
	rps      rate.Limit
	burst    int
}

// NewRateLimiter creates a per-IP rate limiter from the given config.
func NewRateLimiter(cfg config.RateLimitConfig) *RateLimiter {
	rl := &RateLimiter{
		visitors: make(map[string]*visitor),
		rps:      rate.Limit(cfg.RPS),
		burst:    cfg.Burst,
	}

	// Background cleanup of stale visitors every minute.
	go rl.cleanup()

	return rl
}

// Handler returns a Gin middleware that enforces per-IP rate limits.
// It sets X-RateLimit-Limit, X-RateLimit-Remaining, and X-RateLimit-Reset headers.
// Returns 429 with Retry-After when the limit is exceeded.
func (rl *RateLimiter) Handler() gin.HandlerFunc {
	return func(c *gin.Context) {
		ip := c.ClientIP()
		v := rl.getVisitor(ip)

		reservation := v.limiter.Reserve()
		if !reservation.OK() {
			domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded, "rate limit exceeded")
			return
		}

		delay := reservation.Delay()
		if delay > 0 {
			reservation.Cancel()
			retryAfter := int(delay.Seconds()) + 1
			c.Header("Retry-After", strconv.Itoa(retryAfter))
			c.Header("X-RateLimit-Limit", strconv.Itoa(rl.burst))
			c.Header("X-RateLimit-Remaining", "0")
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(delay).Unix(), 10))
			domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded, "rate limit exceeded")
			return
		}

		// Calculate approximate remaining tokens.
		remaining := int(v.limiter.Tokens())
		if remaining < 0 {
			remaining = 0
		}

		c.Header("X-RateLimit-Limit", strconv.Itoa(rl.burst))
		c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))
		c.Next()
	}
}

// getVisitor returns the rate limiter for the given IP, creating one if needed.
func (rl *RateLimiter) getVisitor(ip string) *visitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[ip]
	if !exists {
		v = &visitor{
			limiter: rate.NewLimiter(rl.rps, rl.burst),
		}
		rl.visitors[ip] = v
	}
	v.lastSeen = time.Now()
	return v
}

// cleanup removes visitors that haven't been seen for 3+ minutes.
// Runs in a background goroutine.
func (rl *RateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for ip, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// VisitorCount returns the number of tracked visitors (for testing).
func (rl *RateLimiter) VisitorCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	return len(rl.visitors)
}

// FormatRateLimitHeaders is a helper for setting rate limit headers consistently.
func FormatRateLimitHeaders(limit, remaining int, resetUnix int64) map[string]string {
	return map[string]string{
		"X-RateLimit-Limit":     fmt.Sprintf("%d", limit),
		"X-RateLimit-Remaining": fmt.Sprintf("%d", remaining),
		"X-RateLimit-Reset":     fmt.Sprintf("%d", resetUnix),
	}
}
