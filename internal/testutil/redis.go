//go:build integration

package testutil

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/testcontainers/testcontainers-go"
	tcredis "github.com/testcontainers/testcontainers-go/modules/redis"
	"github.com/testcontainers/testcontainers-go/wait"
)

// RedisContainer wraps a testcontainers Redis instance with a connected client.
type RedisContainer struct {
	Container testcontainers.Container
	Client    *redis.Client
	Addr      string
}

// StartRedis starts a Redis container and returns a connected client.
func StartRedis(ctx context.Context) (*RedisContainer, error) {
	container, err := tcredis.Run(ctx,
		"redis:7-alpine",
		testcontainers.WithWaitStrategy(
			wait.ForLog("Ready to accept connections").
				WithStartupTimeout(30*time.Second),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("start redis container: %w", err)
	}

	connStr, err := container.ConnectionString(ctx)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("get redis connection string: %w", err)
	}

	opts, err := redis.ParseURL(connStr)
	if err != nil {
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("parse redis URL: %w", err)
	}

	client := redis.NewClient(opts)

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		_ = container.Terminate(ctx)
		return nil, fmt.Errorf("ping redis: %w", err)
	}

	return &RedisContainer{
		Container: container,
		Client:    client,
		Addr:      opts.Addr,
	}, nil
}

// Close terminates the client and container.
func (rc *RedisContainer) Close(ctx context.Context) {
	if rc.Client != nil {
		_ = rc.Client.Close()
	}
	if rc.Container != nil {
		_ = rc.Container.Terminate(ctx)
	}
}

// FlushAll removes all keys from all Redis databases.
func (rc *RedisContainer) FlushAll(ctx context.Context) error {
	return rc.Client.FlushAll(ctx).Err()
}
