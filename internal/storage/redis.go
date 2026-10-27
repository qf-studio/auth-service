package storage

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/redis/go-redis/v9"
)

// redisOptions builds the go-redis options. With useTLS the connection is
// encrypted and the server certificate is verified against the system roots.
func redisOptions(addr, password string, db int, useTLS bool) *redis.Options {
	opts := &redis.Options{
		Addr:     addr,
		Password: password,
		DB:       db,
	}
	if useTLS {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		// Decision: TLS 1.2 floor, not 1.3 — managed Redis (e.g. ElastiCache)
		// only offers 1.3 on recent engine versions. RootCAs nil = system roots.
		opts.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host}
	}
	return opts
}

// NewRedisClient creates a Redis client, verifies connectivity with a ping, and returns it.
// useTLS (REDIS_TLS) encrypts the connection. The caller must Close() the client when done.
func NewRedisClient(addr, password string, db int, useTLS bool) (*redis.Client, error) {
	client := redis.NewClient(redisOptions(addr, password, db, useTLS))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		_ = client.Close()
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return client, nil
}
