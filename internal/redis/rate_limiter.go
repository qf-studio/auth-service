package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrRateLimited is returned when the caller has exceeded the allowed request count.
var ErrRateLimited = errors.New("rate limit exceeded")

// RateLimiter checks and enforces per-key rate limits using a Redis sliding window.
type RateLimiter interface {
	// Allow checks whether the action identified by key is within the rate limit.
	// Returns the number of attempts remaining, or ErrRateLimited if the limit is exceeded.
	Allow(ctx context.Context, key string) (remaining int, err error)
}

// rateLimiterConfig holds sliding-window parameters.
type rateLimiterConfig struct {
	client    redis.Cmdable
	keyPrefix string
	maxCount  int
	window    time.Duration
}

// NewResetRateLimiter creates a RateLimiter enforcing max 3 password-reset
// requests per email per hour using a sliding-window counter.
func NewResetRateLimiter(client redis.Cmdable) RateLimiter {
	return &rateLimiterConfig{
		client:    client,
		keyPrefix: "rate:reset:",
		maxCount:  3,
		window:    time.Hour,
	}
}

// NewRateLimiter creates a RateLimiter with custom parameters.
func NewRateLimiter(client redis.Cmdable, keyPrefix string, maxCount int, window time.Duration) RateLimiter {
	return &rateLimiterConfig{
		client:    client,
		keyPrefix: keyPrefix,
		maxCount:  maxCount,
		window:    window,
	}
}

func (r *rateLimiterConfig) key(identifier string) string {
	return fmt.Sprintf("%s%s", r.keyPrefix, identifier)
}

// Allow implements a sliding-window counter using a Redis sorted set.
// Each request is stored as a member with score = current timestamp (microseconds).
// Expired entries outside the window are pruned on every call.
func (r *rateLimiterConfig) Allow(ctx context.Context, identifier string) (int, error) {
	now := time.Now()
	windowStart := now.Add(-r.window)
	k := r.key(identifier)
	nowMicro := float64(now.UnixMicro())
	windowStartMicro := float64(windowStart.UnixMicro())
	member := fmt.Sprintf("%d", now.UnixNano()) // unique member per call

	// Pipeline: remove old entries, add new entry, count entries, set expiry.
	pipe := r.client.Pipeline()
	pipe.ZRemRangeByScore(ctx, k, "-inf", fmt.Sprintf("%f", windowStartMicro))
	pipe.ZAdd(ctx, k, redis.Z{Score: nowMicro, Member: member})
	countCmd := pipe.ZCard(ctx, k)
	pipe.Expire(ctx, k, r.window)

	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("rate limiter pipeline: %w", err)
	}

	count := int(countCmd.Val())
	remaining := r.maxCount - count
	if remaining < 0 {
		// Over limit — remove the entry we just added and return error.
		r.client.ZRem(ctx, k, member)
		return 0, ErrRateLimited
	}
	return remaining, nil
}
