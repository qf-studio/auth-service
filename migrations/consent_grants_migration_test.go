package migrations_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/migrations"
)

// testMigrate returns a *migrate.Migrate wired to the embedded migration
// source and TEST_DATABASE_URL. Skips the test if TEST_DATABASE_URL is not
// set, matching the convention used by internal/storage integration tests.
func testMigrate(t *testing.T) (*migrate.Migrate, string) {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping migration integration test")
	}

	src, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err)

	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	require.NoError(t, err)
	t.Cleanup(func() { _, _ = m.Close() })

	return m, dsn
}

// tableExists reports whether the given table exists in the public schema.
func tableExists(t *testing.T, dsn, table string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var exists bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = 'public' AND table_name = $1)`,
		table,
	).Scan(&exists)
	require.NoError(t, err)

	return exists
}

// TestMigration_ConsentGrantsUpDown proves 000018_consent_grants applies and
// reverts cleanly: after `up` the table exists, after reverting exactly this
// one migration (`steps -1`) it is dropped, matching the down migration's
// contract. Restores the schema to head afterward so other integration
// tests sharing TEST_DATABASE_URL see a fully-migrated database.
func TestMigration_ConsentGrantsUpDown(t *testing.T) {
	m, dsn := testMigrate(t)

	err := m.Up()
	if err != nil && err != migrate.ErrNoChange {
		require.NoError(t, err, "migrate up")
	}
	t.Cleanup(func() {
		if err := m.Up(); err != nil && err != migrate.ErrNoChange {
			t.Errorf("failed to restore schema to head after test: %v", err)
		}
	})

	version, dirty, err := m.Version()
	require.NoError(t, err)
	require.False(t, dirty, "schema should not be dirty after a clean up")
	require.Equal(t, uint(18), version, "expected embedded migrations to be at head version 18")

	require.True(t, tableExists(t, dsn, "consent_grants"), "consent_grants table should exist after migrate up")

	require.NoError(t, m.Steps(-1), "migrate down one step (000018 down)")
	require.False(t, tableExists(t, dsn, "consent_grants"), "consent_grants table should be dropped after reverting 000018")

	version, dirty, err = m.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, uint(17), version, "expected version 17 after reverting 000018")
}
