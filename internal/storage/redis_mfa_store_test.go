package storage_test

import (
	"context"
	"os"
	"testing"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/storage"
)

// testRedis returns a redis.Client for integration tests.
func testRedis(t *testing.T) *redis.Client {
	t.Helper()

	addr := os.Getenv("TEST_REDIS_ADDR")
	if addr == "" {
		t.Skip("TEST_REDIS_ADDR not set, skipping Redis integration test")
	}

	client := redis.NewClient(&redis.Options{Addr: addr})
	t.Cleanup(func() {
		_ = client.FlushDB(context.Background()).Err()
		_ = client.Close()
	})

	require.NoError(t, client.Ping(context.Background()).Err())
	return client
}

// ────────────────────────────────────────────────────────────────────────────
// MFA Token tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisMFAStore_StoreAndConsumeToken(t *testing.T) {
	client := testRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	err := store.StoreMFAToken(ctx, "tok123", "user-abc")
	require.NoError(t, err)

	userID, err := store.ConsumeMFAToken(ctx, "tok123")
	require.NoError(t, err)
	assert.Equal(t, "user-abc", userID)

	// Second consume should fail — single-use.
	_, err = store.ConsumeMFAToken(ctx, "tok123")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

func TestRedisMFAStore_StoreToken_Duplicate(t *testing.T) {
	client := testRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	require.NoError(t, store.StoreMFAToken(ctx, "dup-tok", "user1"))

	err := store.StoreMFAToken(ctx, "dup-tok", "user2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already exists")
}

func TestRedisMFAStore_ConsumeToken_NotFound(t *testing.T) {
	client := testRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	_, err := store.ConsumeMFAToken(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// Failed attempt tracking tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisMFAStore_FailedAttempts(t *testing.T) {
	client := testRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	// Initially zero.
	count, err := store.GetFailedAttempts(ctx, "user-x")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)

	// Increment.
	count, err = store.IncrementFailedAttempts(ctx, "user-x")
	require.NoError(t, err)
	assert.Equal(t, int64(1), count)

	count, err = store.IncrementFailedAttempts(ctx, "user-x")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Verify.
	count, err = store.GetFailedAttempts(ctx, "user-x")
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	// Reset.
	require.NoError(t, store.ResetFailedAttempts(ctx, "user-x"))

	count, err = store.GetFailedAttempts(ctx, "user-x")
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestRedisMFAStore_ResetFailedAttempts_Nonexistent(t *testing.T) {
	client := testRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	// Reset on nonexistent key should not error.
	err := store.ResetFailedAttempts(ctx, "nobody")
	require.NoError(t, err)
}
