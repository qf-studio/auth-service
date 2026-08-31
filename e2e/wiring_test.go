package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/migrations"
)

// migrationFilenamePattern matches golang-migrate's iofs source filenames,
// e.g. "000019_create_api_keys_table.up.sql", capturing the leading
// sequence number.
var migrationFilenamePattern = regexp.MustCompile(`^(\d+)_.*\.up\.sql$`)

// embeddedMigrationHead reads migrations.FS (the same embed.FS
// cmd/migrate/main.go points golang-migrate's iofs source driver at) and
// returns the highest sequence number among its .up.sql files. Reading it
// dynamically — instead of hardcoding a head number in the test — is
// deliberate: a hardcoded head silently goes stale the next time a
// migration is added, exactly the GH-485 head-test trap this test must not
// repeat.
func embeddedMigrationHead(t *testing.T) int {
	t.Helper()

	entries, err := migrations.FS.ReadDir(".")
	require.NoError(t, err, "read embedded migrations FS")

	head := -1
	for _, entry := range entries {
		m := migrationFilenamePattern.FindStringSubmatch(entry.Name())
		if m == nil {
			continue
		}
		var n int
		_, err := fmt.Sscanf(m[1], "%d", &n)
		require.NoError(t, err, "parse migration sequence number from %q", entry.Name())
		if n > head {
			head = n
		}
	}
	require.GreaterOrEqual(t, head, 0, "no .up.sql files found in embedded migrations FS")
	return head
}

// TestWiring_MigrationHeadVersionMatchesEmbeddedFS (GH-494) proves the
// SUT's /auth-migrate up (run once by setupSuite before the SUT itself
// starts, see harness.go runMigrations) actually left schema_migrations at
// the head version embedded in the image, and that it isn't stuck dirty —
// i.e. the migration runner and the embedded migration set genuinely agree,
// not just "the container exited 0".
func TestWiring_MigrationHeadVersionMatchesEmbeddedFS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	wantHead := embeddedMigrationHead(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, suite.PostgresDSN)
	require.NoError(t, err, "connect to postgres")
	defer pool.Close()

	var gotVersion int
	var dirty bool
	err = pool.QueryRow(ctx, "SELECT version, dirty FROM schema_migrations").Scan(&gotVersion, &dirty)
	require.NoError(t, err, "query schema_migrations")

	require.False(t, dirty, "schema_migrations left dirty after migrate up")
	require.Equal(t, wantHead, gotVersion, "schema_migrations version does not match embedded migrations FS head")
}

// TestWiring_AuditLogsGrowAfterAdminAction (GH-494, review-003 wave-2) would
// prove that performing an admin action (create user) increments the
// audit_logs row count, as observed directly against Postgres rather than
// through any API the write path might expose. It is skipped because the
// write path doesn't exist: internal/audit.Service.LogEvent
// (internal/audit/audit.go:120) only buffers events for a zap logger sink —
// nothing in the codebase ever INSERTs into audit_logs. The table exists
// (migrations/000011_create_audit_logs_table.up.sql) and has a *read*
// repository (internal/storage/audit_read_repository.go), but nothing ever
// populates it. The fix PR should unskip this test as its acceptance check.
func TestWiring_AuditLogsGrowAfterAdminAction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	t.Skip("review-003: audit_logs never written (internal/audit.Service only logs to zap, no DB insert) — unskip when fixed")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, suite.PostgresDSN)
	require.NoError(t, err, "connect to postgres")
	defer pool.Close()

	var before int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs").Scan(&before))

	// Admin action: create a user via POST /admin/users.
	body, err := json.Marshal(map[string]string{
		"email":    newE2EEmail("audit-wiring"),
		"password": fakeUserPassword,
		"name":     "E2E Audit Wiring " + uuid.NewString(),
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/users", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "create user request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create user status")

	var after int
	require.NoError(t, pool.QueryRow(ctx, "SELECT count(*) FROM audit_logs").Scan(&after))
	require.Greater(t, after, before, "audit_logs row count must grow after an admin action")
}
