package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/storage"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, redis.Cmdable) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

// ────────────────────────────────────────────────────────────────────────────
// MFA Token tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisMFAStore_StoreMFAToken(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	err := store.StoreMFAToken(ctx, "token-abc", "user-123")
	require.NoError(t, err)
}

func TestRedisMFAStore_StoreMFAToken_DuplicateRejected(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	err := store.StoreMFAToken(ctx, "token-dup", "user-123")
	require.NoError(t, err)

	err = store.StoreMFAToken(ctx, "token-dup", "user-456")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrDuplicateMFA)
}

func TestRedisMFAStore_ConsumeMFAToken(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	err := store.StoreMFAToken(ctx, "token-consume", "user-789")
	require.NoError(t, err)

	userID, err := store.ConsumeMFAToken(ctx, "token-consume")
	require.NoError(t, err)
	assert.Equal(t, "user-789", userID)

	// Second consume should fail (single-use).
	_, err = store.ConsumeMFAToken(ctx, "token-consume")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrMFATokenNotFound)
}

func TestRedisMFAStore_ConsumeMFAToken_NotFound(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	_, err := store.ConsumeMFAToken(ctx, "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrMFATokenNotFound)
}

func TestRedisMFAStore_ConsumeMFAToken_Expired(t *testing.T) {
	mr, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client, storage.WithMFATokenTTL(1*time.Second))
	ctx := context.Background()

	err := store.StoreMFAToken(ctx, "token-expire", "user-111")
	require.NoError(t, err)

	// Fast-forward time in miniredis.
	mr.FastForward(2 * time.Second)

	_, err = store.ConsumeMFAToken(ctx, "token-expire")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrMFATokenNotFound)
}

// ────────────────────────────────────────────────────────────────────────────
// Failed attempt tracking tests
// ────────────────────────────────────────────────────────────────────────────

func TestRedisMFAStore_RecordFailedAttempt(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	count, err := store.RecordFailedAttempt(ctx, "user-fail-1")
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	count, err = store.RecordFailedAttempt(ctx, "user-fail-1")
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestRedisMFAStore_RecordFailedAttempt_MaxExceeded(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client, storage.WithMaxMFAAttempts(3))
	ctx := context.Background()

	for i := 1; i < 3; i++ {
		_, err := store.RecordFailedAttempt(ctx, "user-max")
		require.NoError(t, err)
	}

	// Third attempt should trigger max exceeded.
	count, err := store.RecordFailedAttempt(ctx, "user-max")
	assert.Equal(t, 3, count)
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrMFAMaxAttempts)
}

func TestRedisMFAStore_GetFailedAttempts(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	// No attempts yet.
	count, err := store.GetFailedAttempts(ctx, "user-get-fail")
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	_, err = store.RecordFailedAttempt(ctx, "user-get-fail")
	require.NoError(t, err)

	count, err = store.GetFailedAttempts(ctx, "user-get-fail")
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestRedisMFAStore_ClearFailedAttempts(t *testing.T) {
	_, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	_, err := store.RecordFailedAttempt(ctx, "user-clear")
	require.NoError(t, err)

	err = store.ClearFailedAttempts(ctx, "user-clear")
	require.NoError(t, err)

	count, err := store.GetFailedAttempts(ctx, "user-clear")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}

func TestRedisMFAStore_FailedAttempts_Expire(t *testing.T) {
	mr, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client, storage.WithMFAFailedTTL(1*time.Second))
	ctx := context.Background()

	_, err := store.RecordFailedAttempt(ctx, "user-expire-fail")
	require.NoError(t, err)

	mr.FastForward(2 * time.Second)

	count, err := store.GetFailedAttempts(ctx, "user-expire-fail")
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}
