package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestResetRateLimiter_AllowWithinLimit(t *testing.T) {
	_, client := testRedisClient(t)
	rl := NewResetRateLimiter(client)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		remaining, err := rl.Allow(ctx, "user@example.com")
		require.NoError(t, err)
		assert.GreaterOrEqual(t, remaining, 0, "attempt %d should be allowed", i+1)
	}
}

func TestResetRateLimiter_ExceedsLimit(t *testing.T) {
	_, client := testRedisClient(t)
	rl := NewResetRateLimiter(client)
	ctx := context.Background()

	// Use up all 3 allowed attempts
	for i := 0; i < 3; i++ {
		_, err := rl.Allow(ctx, "user@example.com")
		require.NoError(t, err)
	}

	// 4th attempt should be rate-limited
	_, err := rl.Allow(ctx, "user@example.com")
	assert.ErrorIs(t, err, ErrRateLimited)
}

func TestResetRateLimiter_DifferentKeysIndependent(t *testing.T) {
	_, client := testRedisClient(t)
	rl := NewResetRateLimiter(client)
	ctx := context.Background()

	// Exhaust limit for user A
	for i := 0; i < 3; i++ {
		_, err := rl.Allow(ctx, "a@example.com")
		require.NoError(t, err)
	}

	// User B should still be allowed
	remaining, err := rl.Allow(ctx, "b@example.com")
	require.NoError(t, err)
	assert.Greater(t, remaining, 0)
}

func TestResetRateLimiter_WindowExpiry(t *testing.T) {
	mr, client := testRedisClient(t)
	// Use a short window for testing
	rl := NewRateLimiter(client, "rate:test:", 2, 10*time.Second)
	ctx := context.Background()

	// Use up limit
	for i := 0; i < 2; i++ {
		_, err := rl.Allow(ctx, "user@example.com")
		require.NoError(t, err)
	}
	_, err := rl.Allow(ctx, "user@example.com")
	assert.ErrorIs(t, err, ErrRateLimited)

	// Fast-forward past window
	mr.FastForward(11 * time.Second)

	// Should be allowed again
	remaining, err := rl.Allow(ctx, "user@example.com")
	require.NoError(t, err)
	assert.Greater(t, remaining, 0)
}

func TestNewRateLimiter_CustomParams(t *testing.T) {
	_, client := testRedisClient(t)
	rl := NewRateLimiter(client, "rate:custom:", 5, 30*time.Second)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, err := rl.Allow(ctx, "test-key")
		require.NoError(t, err)
	}

	_, err := rl.Allow(ctx, "test-key")
	assert.ErrorIs(t, err, ErrRateLimited)
}
