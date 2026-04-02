package redis

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// ErrTokenNotFound is returned when a token lookup finds no matching key.
var ErrTokenNotFound = errors.New("token not found")

// TokenStore defines operations for hashed reset-token persistence with TTL.
type TokenStore interface {
	// Store saves a hashed token keyed by tokenID with the given TTL.
	Store(ctx context.Context, tokenID string, hashedToken string, ttl time.Duration) error
	// Retrieve returns the hashed token for tokenID, or ErrTokenNotFound.
	Retrieve(ctx context.Context, tokenID string) (string, error)
	// Delete removes a token by ID. Returns ErrTokenNotFound if absent.
	Delete(ctx context.Context, tokenID string) error
}

// redisTokenStore implements TokenStore backed by Redis.
type redisTokenStore struct {
	client    redis.Cmdable
	keyPrefix string
}

// NewTokenStore creates a TokenStore backed by the given Redis client.
func NewTokenStore(client redis.Cmdable) TokenStore {
	return &redisTokenStore{
		client:    client,
		keyPrefix: "reset_token:",
	}
}

func (s *redisTokenStore) key(tokenID string) string {
	return fmt.Sprintf("%s%s", s.keyPrefix, tokenID)
}

func (s *redisTokenStore) Store(ctx context.Context, tokenID string, hashedToken string, ttl time.Duration) error {
	if err := s.client.Set(ctx, s.key(tokenID), hashedToken, ttl).Err(); err != nil {
		return fmt.Errorf("store token: %w", err)
	}
	return nil
}

func (s *redisTokenStore) Retrieve(ctx context.Context, tokenID string) (string, error) {
	val, err := s.client.Get(ctx, s.key(tokenID)).Result()
	if errors.Is(err, redis.Nil) {
		return "", ErrTokenNotFound
	}
	if err != nil {
		return "", fmt.Errorf("retrieve token: %w", err)
	}
	return val, nil
}

func (s *redisTokenStore) Delete(ctx context.Context, tokenID string) error {
	n, err := s.client.Del(ctx, s.key(tokenID)).Result()
	if err != nil {
		return fmt.Errorf("delete token: %w", err)
	}
	if n == 0 {
		return ErrTokenNotFound
	}
	return nil
}
