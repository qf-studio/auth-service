package middleware

import (
	"context"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/time/rate"

	"github.com/qf-studio/auth-service/internal/domain"
)

const apiKeyHeader = "X-API-Key"

// APIKeyInfo holds the validated API key metadata returned by the validator.
type APIKeyInfo struct {
	ClientID   string
	ClientType domain.ClientType
	Scopes     []string
	RateLimit  int // requests per second; 0 means no per-key limit
}

// APIKeyValidator defines the operations required by APIKeyMiddleware.
type APIKeyValidator interface {
	// ValidateAPIKey checks the raw API key (with qf_ak_ prefix) and returns
	// its associated metadata. Returns an error if the key is invalid, expired,
	// or revoked.
	ValidateAPIKey(ctx context.Context, rawKey string) (*APIKeyInfo, error)
}

// apiKeyVisitor tracks per-key rate limit state.
type apiKeyVisitor struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// APIKeyRateLimiter manages per-key token bucket rate limiters.
type APIKeyRateLimiter struct {
	mu       sync.Mutex
	visitors map[string]*apiKeyVisitor
}

// NewAPIKeyRateLimiter creates a per-key rate limiter.
func NewAPIKeyRateLimiter() *APIKeyRateLimiter {
	rl := &APIKeyRateLimiter{
		visitors: make(map[string]*apiKeyVisitor),
	}
	go rl.cleanup()
	return rl
}

// getVisitor returns the rate limiter for the given key, creating one if the
// limit has changed or the key is seen for the first time.
func (rl *APIKeyRateLimiter) getVisitor(clientID string, rps int) *apiKeyVisitor {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	v, exists := rl.visitors[clientID]
	if !exists || int(v.limiter.Limit()) != rps {
		v = &apiKeyVisitor{
			limiter: rate.NewLimiter(rate.Limit(rps), rps),
		}
		rl.visitors[clientID] = v
	}
	v.lastSeen = time.Now()
	return v
}

// cleanup removes visitors that haven't been seen for 3+ minutes.
func (rl *APIKeyRateLimiter) cleanup() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		rl.mu.Lock()
		for id, v := range rl.visitors {
			if time.Since(v.lastSeen) > 3*time.Minute {
				delete(rl.visitors, id)
			}
		}
		rl.mu.Unlock()
	}
}

// APIKeyMiddleware returns a Gin middleware that authenticates requests via
// the X-API-Key header. Behaviour:
//
//  1. If no X-API-Key header is present, calls c.Next() (fall-through to
//     Bearer token auth).
//  2. Validates the key via the APIKeyValidator.
//  3. Enforces per-key rate limits when the key has a non-zero RateLimit.
//  4. Stores *domain.TokenClaims under "claims" and ClientID under "user_id",
//     matching the context keys set by AuthMiddleware.
//
// Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining,
// X-RateLimit-Reset) are set following the pattern in ratelimit.go.
func APIKeyMiddleware(validator APIKeyValidator, rateLimiter *APIKeyRateLimiter) gin.HandlerFunc {
	return func(c *gin.Context) {
		rawKey := c.GetHeader(apiKeyHeader)
		if rawKey == "" {
			c.Next()
			return
		}

		info, err := validator.ValidateAPIKey(c.Request.Context(), rawKey)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid or expired API key")
			return
		}

		// Enforce per-key rate limit if configured.
		if info.RateLimit > 0 {
			v := rateLimiter.getVisitor(info.ClientID, info.RateLimit)
			reservation := v.limiter.Reserve()
			if !reservation.OK() {
				domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded,
					"API key rate limit exceeded")
				return
			}

			delay := reservation.Delay()
			if delay > 0 {
				reservation.Cancel()
				retryAfter := int(delay.Seconds()) + 1
				c.Header("Retry-After", strconv.Itoa(retryAfter))
				c.Header("X-RateLimit-Limit", strconv.Itoa(info.RateLimit))
				c.Header("X-RateLimit-Remaining", "0")
				c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(delay).Unix(), 10))
				domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded,
					"API key rate limit exceeded")
				return
			}

			remaining := int(v.limiter.Tokens())
			if remaining < 0 {
				remaining = 0
			}
			c.Header("X-RateLimit-Limit", strconv.Itoa(info.RateLimit))
			c.Header("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Header("X-RateLimit-Reset", strconv.FormatInt(time.Now().Add(time.Second).Unix(), 10))
		}

		// Populate the same context keys used by AuthMiddleware so downstream
		// handlers (RBAC, etc.) work identically.
		claims := &domain.TokenClaims{
			Subject:    info.ClientID,
			Scopes:     info.Scopes,
			ClientType: info.ClientType,
		}
		c.Set(claimsContextKey, claims)
		c.Set(userIDContextKey, info.ClientID)
		c.Next()
	}
}
