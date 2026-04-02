//go:build integration

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisContainer_Ping(t *testing.T) {
	ctx := context.Background()
	err := testRedis.Client.Ping(ctx).Err()
	require.NoError(t, err, "redis client should be pingable")
}

func TestRedisContainer_Addr(t *testing.T) {
	assert.NotEmpty(t, testRedis.Addr, "redis addr should be set")
}

func TestRedisContainer_SetGet(t *testing.T) {
	ctx := context.Background()

	err := testRedis.Client.Set(ctx, "test_key", "test_value", 0).Err()
	require.NoError(t, err)

	val, err := testRedis.Client.Get(ctx, "test_key").Result()
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Cleanup
	_, _ = testRedis.Client.Del(ctx, "test_key").Result()
}

func TestRedisContainer_FlushAll(t *testing.T) {
	ctx := context.Background()

	err := testRedis.Client.Set(ctx, "flush_key", "value", 0).Err()
	require.NoError(t, err)

	err = testRedis.FlushAll(ctx)
	require.NoError(t, err)

	exists, err := testRedis.Client.Exists(ctx, "flush_key").Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "key should not exist after flush")
}
