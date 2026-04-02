//go:build integration

package testutil

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTruncateTables_NoTablesExist(t *testing.T) {
	ctx := context.Background()

	// With no migrations run, default tables don't exist. Should succeed gracefully.
	err := TruncateTables(ctx, testPG.Pool)
	require.NoError(t, err, "truncate should succeed even when tables don't exist")
}

func TestTruncateTables_WithCreatedTable(t *testing.T) {
	ctx := context.Background()

	// Create a temporary test table
	_, err := testPG.Pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS test_cleanup (id SERIAL PRIMARY KEY, name TEXT)`)
	require.NoError(t, err)

	// Insert data
	_, err = testPG.Pool.Exec(ctx, `INSERT INTO test_cleanup (name) VALUES ('row1'), ('row2')`)
	require.NoError(t, err)

	// Truncate specific table
	err = TruncateTables(ctx, testPG.Pool, "test_cleanup")
	require.NoError(t, err)

	// Verify empty
	var count int
	err = testPG.Pool.QueryRow(ctx, `SELECT COUNT(*) FROM test_cleanup`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count, "table should be empty after truncate")

	// Cleanup
	_, _ = testPG.Pool.Exec(ctx, `DROP TABLE test_cleanup`)
}
