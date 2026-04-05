package oauth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestRedis(t *testing.T) (redis.Cmdable, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	return rdb, mr
}

func TestStateManager_GenerateAndValidate(t *testing.T) {
	rdb, _ := newTestRedis(t)
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	sm := NewStateManager(rdb, secret, 10*time.Minute)

	ctx := context.Background()

	t.Run("round-trip generate and validate", func(t *testing.T) {
		token, err := sm.Generate(ctx, "google")
		require.NoError(t, err)
		assert.NotEmpty(t, token)
		assert.Contains(t, token, ".")

		provider, err := sm.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "google", provider)
	})

	t.Run("one-time consumption (replay rejected)", func(t *testing.T) {
		token, err := sm.Generate(ctx, "github")
		require.NoError(t, err)

		// First validation succeeds.
		provider, err := sm.Validate(ctx, token)
		require.NoError(t, err)
		assert.Equal(t, "github", provider)

		// Second validation fails — token already consumed.
		_, err = sm.Validate(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "already consumed")
	})

	t.Run("invalid format rejected", func(t *testing.T) {
		_, err := sm.Validate(ctx, "no-dot-here")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "invalid state token format")
	})

	t.Run("tampered signature rejected", func(t *testing.T) {
		token, err := sm.Generate(ctx, "apple")
		require.NoError(t, err)

		// Tamper with the last character.
		tampered := token[:len(token)-1] + "X"
		_, err = sm.Validate(ctx, tampered)
		assert.Error(t, err)
	})

	t.Run("wrong HMAC key rejected", func(t *testing.T) {
		token, err := sm.Generate(ctx, "google")
		require.NoError(t, err)

		wrongSM := NewStateManager(rdb, []byte("wrong-secret-key-is-different!!!"), 10*time.Minute)
		_, err = wrongSM.Validate(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "signature mismatch")
	})
}

func TestStateManager_Expiry(t *testing.T) {
	rdb, mr := newTestRedis(t)
	secret := []byte("test-hmac-secret-32-bytes-long!!")
	ttl := 5 * time.Minute
	sm := NewStateManager(rdb, secret, ttl)

	ctx := context.Background()

	t.Run("expired token rejected", func(t *testing.T) {
		now := time.Now()
		sm.nowFunc = func() time.Time { return now }

		token, err := sm.Generate(ctx, "google")
		require.NoError(t, err)

		// Advance clock past TTL.
		sm.nowFunc = func() time.Time { return now.Add(6 * time.Minute) }

		_, err = sm.Validate(ctx, token)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "expired")
	})

	t.Run("redis TTL causes key expiry", func(t *testing.T) {
		now := time.Now()
		sm.nowFunc = func() time.Time { return now }

		token, err := sm.Generate(ctx, "github")
		require.NoError(t, err)

		// Fast-forward miniredis to expire the key.
		mr.FastForward(6 * time.Minute)

		_, err = sm.Validate(ctx, token)
		assert.Error(t, err)
	})
}
