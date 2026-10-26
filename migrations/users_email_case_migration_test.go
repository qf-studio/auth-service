package migrations_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang-migrate/migrate/v4"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

const defaultTenantID = "00000000-0000-0000-0000-000000000001"

// TestMigration_UsersEmailCaseInsensitiveUnique proves 000022 applies on clean
// data, enforces case-insensitive uniqueness, and refuses to run (leaving the
// data untouched) when two rows in a tenant differ only by email case.
func TestMigration_UsersEmailCaseInsensitiveUnique(t *testing.T) {
	m, dsn := testMigrate(t)

	err := m.Up()
	if err != nil && err != migrate.ErrNoChange {
		require.NoError(t, err, "migrate up")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel) // registered first, so it runs after the restore cleanup below

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	insert := func(id, email string) error {
		_, execErr := pool.Exec(ctx,
			`INSERT INTO users (id, tenant_id, email, password_hash, name) VALUES ($1, $2, $3, 'x', 'n')`,
			id, defaultTenantID, email)
		return execErr
	}
	cleanup := func() {
		_, delErr := pool.Exec(ctx, `DELETE FROM users WHERE id LIKE 'gh526-%'`)
		require.NoError(t, delErr)
	}
	t.Cleanup(func() {
		cleanup()
		if upErr := m.Up(); upErr != nil && upErr != migrate.ErrNoChange {
			t.Errorf("failed to restore schema to head after test: %v", upErr)
		}
	})

	// Applied on clean data: the index rejects a case-variant duplicate.
	require.True(t, indexExists(t, dsn, "idx_users_tenant_lower_email"))
	require.NoError(t, insert("gh526-a", "Alice@X.com"))
	require.Error(t, insert("gh526-b", "alice@x.com"), "case-variant duplicate should be rejected")
	cleanup()

	// Roll back to 000021 (no case-insensitive index), then seed a collision.
	require.NoError(t, m.Migrate(21))
	require.False(t, indexExists(t, dsn, "idx_users_tenant_lower_email"))
	require.NoError(t, insert("gh526-a", "Alice@X.com"))
	require.NoError(t, insert("gh526-b", "alice@x.com"))

	err = m.Migrate(22)
	require.Error(t, err, "migration must fail on case-colliding emails")
	require.Contains(t, err.Error(), "differ only by case")
	require.Contains(t, err.Error(), "1 (tenant_id, lower(email)) group(s)")
	require.False(t, indexExists(t, dsn, "idx_users_tenant_lower_email"))

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE id LIKE 'gh526-%'`).Scan(&n))
	require.Equal(t, 2, n, "colliding rows must not be merged or deleted")

	// A failed migration leaves the schema dirty; clear it, resolve, retry.
	require.NoError(t, m.Force(21))
	cleanup()
	require.NoError(t, m.Migrate(22))
	require.True(t, indexExists(t, dsn, "idx_users_tenant_lower_email"))
}
