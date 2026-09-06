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

// columnExists reports whether the given column exists on the given table in
// the public schema.
func columnExists(t *testing.T, dsn, table, column string) bool {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()

	var exists bool
	err = pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1 AND column_name = $2)`,
		table, column,
	).Scan(&exists)
	require.NoError(t, err)

	return exists
}

// TestMigration_ConsentGrantsUpDown proves 000018_consent_grants,
// 000019_create_api_keys_table, and 000020_add_client_audience apply and
// revert cleanly: after `up` both tables exist and clients has an audience
// column; reverting the newest migration (000020) drops that column, and
// reverting the next one (`steps -1` again, undoing 000019) drops api_keys
// while consent_grants — applied by the earlier, non-reverted 000018 — is
// untouched. Restores the schema to head afterward so other integration
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
	require.Equal(t, uint(20), version, "expected embedded migrations to be at head version 20")

	require.True(t, tableExists(t, dsn, "consent_grants"), "consent_grants table should exist after migrate up")
	require.True(t, tableExists(t, dsn, "api_keys"), "api_keys table should exist after migrate up")
	require.True(t, columnExists(t, dsn, "clients", "audience"), "clients.audience column should exist after migrate up")

	require.NoError(t, m.Steps(-1), "migrate down one step (000020 down)")
	require.False(t, columnExists(t, dsn, "clients", "audience"), "clients.audience column should be dropped after reverting 000020")

	version, dirty, err = m.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, uint(19), version, "expected version 19 after reverting 000020")

	require.NoError(t, m.Steps(-1), "migrate down one step (000019 down)")
	require.False(t, tableExists(t, dsn, "api_keys"), "api_keys table should be dropped after reverting 000019")
	require.True(t, tableExists(t, dsn, "consent_grants"), "consent_grants table should be unaffected by reverting 000019")

	version, dirty, err = m.Version()
	require.NoError(t, err)
	require.False(t, dirty)
	require.Equal(t, uint(18), version, "expected version 18 after reverting 000019")
}
