package main

import (
	"os"
	"os/exec"
	"testing"

	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/qf-studio/auth-service/migrations"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCLIBuilds(t *testing.T) {
	cmd := exec.Command("go", "build", "-o", os.DevNull, "./")
	cmd.Dir = "."
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", out)
}

func TestMigrationSourceEmbeds(t *testing.T) {
	src, err := iofs.New(migrations.FS, ".")
	require.NoError(t, err, "failed to create iofs source from embedded migrations")

	// Verify we can read the first migration version.
	version, err := src.First()
	require.NoError(t, err, "no migrations found in embedded FS")
	assert.Equal(t, uint(1), version, "first migration version should be 1")
}

func TestDatabaseURLFromEnv(t *testing.T) {
	t.Run("DATABASE_URL takes precedence", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "postgres://u:p@host:5432/db?sslmode=disable")
		got, err := databaseURL()
		require.NoError(t, err)
		assert.Equal(t, "postgres://u:p@host:5432/db?sslmode=disable", got)
	})

	t.Run("builds URL from POSTGRES_* vars", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("POSTGRES_HOST", "localhost")
		t.Setenv("POSTGRES_PORT", "5433")
		t.Setenv("POSTGRES_DB", "testdb")
		t.Setenv("POSTGRES_USER", "testuser")
		t.Setenv("POSTGRES_PASSWORD", "testpass")
		t.Setenv("POSTGRES_SSLMODE", "require")

		got, err := databaseURL()
		require.NoError(t, err)
		assert.Equal(t, "postgres://testuser:testpass@localhost:5433/testdb?sslmode=require", got)
	})

	t.Run("errors when vars missing", func(t *testing.T) {
		t.Setenv("DATABASE_URL", "")
		t.Setenv("POSTGRES_HOST", "")
		t.Setenv("POSTGRES_DB", "")
		t.Setenv("POSTGRES_USER", "")
		t.Setenv("POSTGRES_PASSWORD", "")

		_, err := databaseURL()
		assert.Error(t, err)
	})
}

func TestRunUnknownCommand(t *testing.T) {
	// We can't create a real *migrate.Migrate without a DB, but we can verify
	// that an unknown command returns the expected error.
	err := run(nil, "bogus")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown command")
}
