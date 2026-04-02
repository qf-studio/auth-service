package redis

import (
	"context"
	"testing"

	"github.com/alicebob/miniredis/v2"
	goredis "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClient_Success(t *testing.T) {
	mr := miniredis.RunT(t)

	client, err := NewClient(context.Background(), Config{
		Host: mr.Host(),
		Port: mr.Server().Addr().Port,
	})
	require.NoError(t, err)
	require.NotNil(t, client)
	_ = client.Close()
}

func TestNewClient_ConnectionFailure(t *testing.T) {
	client, err := NewClient(context.Background(), Config{
		Host: "127.0.0.1",
		Port: 1, // unlikely to have Redis here
	})
	assert.Error(t, err)
	assert.Nil(t, client)
	assert.Contains(t, err.Error(), "redis ping failed")
}

// testRedisClient creates a miniredis instance and returns a connected go-redis client.
func testRedisClient(t *testing.T) (*miniredis.Miniredis, *goredis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := goredis.NewClient(&goredis.Options{
		Addr: mr.Addr(),
	})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}
