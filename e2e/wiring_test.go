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

// TestWiring_AuditLogsGrowAfterAdminAction (GH-494, review-003 wave-2;
// acceptance check for GH-527) proves that an admin action (create user)
// reaches the audit_logs table, observed directly in Postgres rather than
// through any API the write path might expose. The admin request carries the
// admin bearer token through suite.HTTPClient (GH-524). Events are persisted
// asynchronously in batches (audit.DefaultFlushInterval), so the check polls
// for the row; it matches the event by type and target so audit rows written
// by other tests cannot satisfy it.
func TestWiring_AuditLogsGrowAfterAdminAction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, suite.PostgresDSN)
	require.NoError(t, err, "connect to postgres")
	defer pool.Close()

	// Admin action: create a user via POST /admin/users.
	body, err := json.Marshal(map[string]string{
		"email":    newE2EEmail("audit-wiring"),
		"password": fakeUserPassword,
		"name":     "E2E Audit Wiring " + uuid.NewString(),
	})
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, suite.AdminBaseURL+"/admin/users", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "create user request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create user status")

	var created struct {
		ID string `json:"id"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created), "decode create user response")
	require.NotEmpty(t, created.ID, "create user response must carry the user id")

	require.Eventually(t, func() bool {
		var n int
		err := pool.QueryRow(ctx,
			"SELECT count(*) FROM audit_logs WHERE event_type = $1 AND target_id = $2",
			"admin_user_create", created.ID,
		).Scan(&n)
		return err == nil && n > 0
	}, 15*time.Second, 250*time.Millisecond, "audit_logs must get an admin_user_create row for the created user")
}
