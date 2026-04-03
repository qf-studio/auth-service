package health

import (
	"context"
	"time"

	"github.com/redis/go-redis/v9"
)

// RedisChecker checks Redis connectivity by pinging the client.
type RedisChecker struct {
	client *redis.Client
}

// NewRedisChecker creates a checker for the given Redis client.
func NewRedisChecker(client *redis.Client) *RedisChecker {
	return &RedisChecker{client: client}
}

// Name returns the checker identifier.
func (c *RedisChecker) Name() string { return "redis" }

// Check pings the Redis server and returns the result.
func (c *RedisChecker) Check(ctx context.Context) Result {
	start := time.Now()
	if err := c.client.Ping(ctx).Err(); err != nil {
		return Result{
			Status:   StatusUnhealthy,
			Message:  err.Error(),
			Duration: time.Since(start),
		}
	}
	return Result{
		Status:   StatusHealthy,
		Duration: time.Since(start),
	}
}
