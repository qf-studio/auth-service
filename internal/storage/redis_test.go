package storage_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/storage"
)

func TestNewRedisClient_InvalidAddr(t *testing.T) {
	// Unreachable address — ping must fail within 5 s.
	client, err := storage.NewRedisClient("localhost:19999", "", 0)
	assert.Nil(t, client)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "redis ping failed")
}
