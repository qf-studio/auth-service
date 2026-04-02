//go:build integration

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPostgresContainer_Ping(t *testing.T) {
	ctx := context.Background()
	err := testPG.Pool.Ping(ctx)
	require.NoError(t, err, "postgres pool should be pingable")
}

func TestPostgresContainer_DSN(t *testing.T) {
	assert.NotEmpty(t, testPG.DSN, "DSN should be set")
	assert.Contains(t, testPG.DSN, "postgres://", "DSN should be a postgres URL")
}

func TestPostgresContainer_Query(t *testing.T) {
	ctx := context.Background()
	var result int
	err := testPG.Pool.QueryRow(ctx, "SELECT 1").Scan(&result)
	require.NoError(t, err)
	assert.Equal(t, 1, result)
}
