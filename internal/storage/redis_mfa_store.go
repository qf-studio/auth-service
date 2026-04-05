package storage

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// mfaTokenPrefix is the Redis key prefix for single-use MFA tokens.
	mfaTokenPrefix = "mfa:token:"

	// mfaFailPrefix is the Redis key prefix for failed-attempt counters.
	mfaFailPrefix = "mfa:fail:"

	// mfaTokenTTL is the lifetime of a temporary MFA token.
	mfaTokenTTL = 5 * time.Minute

	// mfaFailWindowTTL is the window for tracking failed MFA attempts.
	mfaFailWindowTTL = 15 * time.Minute
)

// RedisMFAStore provides Redis-based storage for temporary MFA tokens and
// failed-attempt tracking.
type RedisMFAStore struct {
	client *redis.Client
}

// NewRedisMFAStore creates a new Redis-backed MFA store.
func NewRedisMFAStore(client *redis.Client) *RedisMFAStore {
	return &RedisMFAStore{client: client}
}

// StoreMFAToken saves a single-use MFA token that maps to a user ID.
// The token expires after 5 minutes and can only be consumed once.
func (s *RedisMFAStore) StoreMFAToken(ctx context.Context, token string, userID string) error {
	key := mfaTokenPrefix + token
	result, err := s.client.SetArgs(ctx, key, userID, redis.SetArgs{
		Mode: "NX",
		TTL:  mfaTokenTTL,
	}).Result()
	if err != nil {
		return fmt.Errorf("store mfa token: %w", err)
	}
	if result != "OK" {
		return fmt.Errorf("mfa token already exists")
	}
	return nil
}

// ConsumeMFAToken retrieves and deletes an MFA token (single-use).
// Returns the associated user ID, or ErrNotFound if the token does not exist
// or has already been consumed.
func (s *RedisMFAStore) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	key := mfaTokenPrefix + token
	userID, err := s.client.GetDel(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrNotFound
		}
		return "", fmt.Errorf("consume mfa token: %w", err)
	}
	return userID, nil
}

// IncrementFailedAttempts increments the failed MFA attempt counter for a user
// and returns the new count. The counter resets after the fail window expires.
func (s *RedisMFAStore) IncrementFailedAttempts(ctx context.Context, userID string) (int64, error) {
	key := mfaFailPrefix + userID

	pipe := s.client.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, mfaFailWindowTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return 0, fmt.Errorf("increment failed attempts: %w", err)
	}
	return incrCmd.Val(), nil
}

// GetFailedAttempts returns the current failed MFA attempt count for a user.
func (s *RedisMFAStore) GetFailedAttempts(ctx context.Context, userID string) (int64, error) {
	key := mfaFailPrefix + userID
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("get failed attempts: %w", err)
	}
	count, err := strconv.ParseInt(val, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse failed attempts: %w", err)
	}
	return count, nil
}

// ResetFailedAttempts clears the failed attempt counter for a user.
func (s *RedisMFAStore) ResetFailedAttempts(ctx context.Context, userID string) error {
	key := mfaFailPrefix + userID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("reset failed attempts: %w", err)
	}
	return nil
}
