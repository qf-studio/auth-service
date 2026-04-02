package redis

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTokenStore_StoreAndRetrieve(t *testing.T) {
	_, client := testRedisClient(t)
	store := NewTokenStore(client)
	ctx := context.Background()

	err := store.Store(ctx, "tok123", "hashed_value_abc", 10*time.Minute)
	require.NoError(t, err)

	val, err := store.Retrieve(ctx, "tok123")
	require.NoError(t, err)
	assert.Equal(t, "hashed_value_abc", val)
}

func TestTokenStore_RetrieveNotFound(t *testing.T) {
	_, client := testRedisClient(t)
	store := NewTokenStore(client)
	ctx := context.Background()

	_, err := store.Retrieve(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTokenStore_Delete(t *testing.T) {
	_, client := testRedisClient(t)
	store := NewTokenStore(client)
	ctx := context.Background()

	err := store.Store(ctx, "tok456", "hash456", 10*time.Minute)
	require.NoError(t, err)

	err = store.Delete(ctx, "tok456")
	require.NoError(t, err)

	_, err = store.Retrieve(ctx, "tok456")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTokenStore_DeleteNotFound(t *testing.T) {
	_, client := testRedisClient(t)
	store := NewTokenStore(client)
	ctx := context.Background()

	err := store.Delete(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}

func TestTokenStore_TTLExpiry(t *testing.T) {
	mr, client := testRedisClient(t)
	store := NewTokenStore(client)
	ctx := context.Background()

	err := store.Store(ctx, "tok_ttl", "hash_ttl", 1*time.Second)
	require.NoError(t, err)

	// Fast-forward miniredis clock past TTL
	mr.FastForward(2 * time.Second)

	_, err = store.Retrieve(ctx, "tok_ttl")
	assert.ErrorIs(t, err, ErrTokenNotFound)
}
