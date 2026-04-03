// Package middleware provides HTTP middleware for the auth service including
// rate limiting, security headers, CORS, and request size/timeout limits.
package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"golang.org/x/time/rate"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

// progressiveDelayStep is the incremental delay added per failed attempt
// beyond the ProgressiveDelayAfter threshold (NIST SP 800-63-4 guidance).
const progressiveDelayStep = 30 * time.Second

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

// --- Redis-backed per-account rate limiter ---

const (
	accountFailPrefix = "rl:fail:" // Redis key prefix for failed attempt counters.
	accountLockPrefix = "rl:lock:" // Redis key prefix for account lockout flags.
)

// AccountRateLimiter tracks per-account failed authentication attempts in Redis
// and enforces progressive delay and lockout per NIST SP 800-63-4.
type AccountRateLimiter struct {
	rdb                   *redis.Client
	progressiveDelayAfter int
	maxFailedAttempts     int
	lockoutDuration       time.Duration
}

// NewAccountRateLimiter creates a Redis-backed per-account rate limiter.
func NewAccountRateLimiter(rdb *redis.Client, cfg config.RateLimitConfig) *AccountRateLimiter {
	return &AccountRateLimiter{
		rdb:                   rdb,
		progressiveDelayAfter: cfg.ProgressiveDelayAfter,
		maxFailedAttempts:     cfg.MaxFailedAttempts,
		lockoutDuration:       cfg.LockoutDuration,
	}
}

// CheckAccount verifies whether the account is allowed to attempt authentication.
// Returns a Gin middleware abort if the account is locked out or must wait
// for progressive delay. Callers should call RecordFailure on auth failure
// and ResetAttempts on success.
func (a *AccountRateLimiter) CheckAccount(ctx context.Context, account string) (blocked bool, retryAfter time.Duration, err error) {
	lockKey := accountLockPrefix + account

	// Check lockout first.
	ttl, err := a.rdb.TTL(ctx, lockKey).Result()
	if err != nil {
		return false, 0, fmt.Errorf("check account lockout: %w", err)
	}
	if ttl > 0 {
		return true, ttl, nil
	}

	// Check progressive delay.
	failKey := accountFailPrefix + account
	attempts, err := a.rdb.Get(ctx, failKey).Int64()
	if err != nil && err != redis.Nil {
		return false, 0, fmt.Errorf("get failed attempts: %w", err)
	}

	if int(attempts) >= a.progressiveDelayAfter {
		delay := time.Duration(int(attempts)-a.progressiveDelayAfter+1) * progressiveDelayStep
		return false, delay, nil
	}

	return false, 0, nil
}

// RecordFailure increments the failed attempt counter for the account.
// If MaxFailedAttempts is reached, the account is locked out for LockoutDuration.
func (a *AccountRateLimiter) RecordFailure(ctx context.Context, account string) (attempts int64, locked bool, err error) {
	failKey := accountFailPrefix + account

	pipe := a.rdb.Pipeline()
	incrCmd := pipe.Incr(ctx, failKey)
	// Set a TTL on the failure counter so it auto-expires. Use lockout duration * 2
	// as an upper bound so counters don't persist forever.
	pipe.Expire(ctx, failKey, a.lockoutDuration*2)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, false, fmt.Errorf("record failure: %w", err)
	}

	attempts = incrCmd.Val()

	if int(attempts) >= a.maxFailedAttempts {
		lockKey := accountLockPrefix + account
		if err := a.rdb.Set(ctx, lockKey, "1", a.lockoutDuration).Err(); err != nil {
			return attempts, false, fmt.Errorf("set lockout: %w", err)
		}
		return attempts, true, nil
	}

	return attempts, false, nil
}

// ResetAttempts clears the failed attempt counter and lockout for the account
// (called after successful authentication).
func (a *AccountRateLimiter) ResetAttempts(ctx context.Context, account string) error {
	pipe := a.rdb.Pipeline()
	pipe.Del(ctx, accountFailPrefix+account)
	pipe.Del(ctx, accountLockPrefix+account)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("reset attempts: %w", err)
	}
	return nil
}

// AccountRateLimitMiddleware returns a Gin middleware that checks per-account
// lockout and progressive delay before allowing auth requests through.
// It expects the account identifier in the "email" form field or JSON body
// already parsed into gin context key "account_id".
func (a *AccountRateLimiter) AccountRateLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		account := c.GetString("account_id")
		if account == "" {
			// No account context — skip account-level check.
			c.Next()
			return
		}

		blocked, retryAfter, err := a.CheckAccount(c.Request.Context(), account)
		if err != nil {
			domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError, "rate limit check failed")
			return
		}

		if blocked {
			retrySeconds := int(retryAfter.Seconds()) + 1
			c.Header("Retry-After", strconv.Itoa(retrySeconds))
			domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded, "account locked due to too many failed attempts")
			return
		}

		if retryAfter > 0 {
			remaining := a.maxFailedAttempts - a.currentAttempts(c.Request.Context(), account)
			if remaining < 0 {
				remaining = 0
			}
			c.Header("X-RateLimit-Limit", strconv.Itoa(a.maxFailedAttempts))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
		}

		c.Next()
	}
}

// currentAttempts is a helper that reads the current attempt count (best-effort).
func (a *AccountRateLimiter) currentAttempts(ctx context.Context, account string) int {
	val, err := a.rdb.Get(ctx, accountFailPrefix+account).Int64()
	if err != nil {
		return 0
	}
	return int(val)
}
