package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

// createAuditLogsTable mirrors migrations 000011 + 000015 + 000023.
func createAuditLogsTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := pool.Exec(ctx, `
		CREATE TABLE IF NOT EXISTS audit_logs (
			id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
			tenant_id   UUID        NOT NULL REFERENCES tenants (id),
			event_type  TEXT        NOT NULL,
			actor_id    TEXT        NOT NULL DEFAULT '',
			target_id   TEXT        NOT NULL DEFAULT '',
			ip          TEXT        NOT NULL DEFAULT '',
			user_agent  TEXT        NOT NULL DEFAULT '',
			metadata    JSONB       NOT NULL DEFAULT '{}',
			created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
		)`)
	require.NoError(t, err)
}

type recordingDrops struct{ counts map[string]int }

func (d *recordingDrops) RecordAuditDropped(reason string, n int) { d.counts[reason] += n }

func TestPostgresAuditSink_PersistsEventsAndAdminActivityReturnsThem(t *testing.T) {
	pool := testPool(t)
	createAuditLogsTable(t, pool)
	ctx := context.Background()

	userID := uuid.NewString()
	_, err := pool.Exec(ctx, `INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'Audit Test')`,
		userID, userID+"@example.com")
	require.NoError(t, err)

	drops := &recordingDrops{counts: map[string]int{}}
	svc := audit.NewServiceWithOptions(zap.NewNop(), 64, audit.Options{
		Sink:  storage.NewPostgresAuditSink(pool),
		Drops: drops,
	})

	base := time.Now().UTC().Truncate(time.Microsecond).Add(-time.Minute)
	events := []audit.Event{
		{Type: audit.EventLoginSuccess, ActorID: userID, TargetID: userID, IP: "203.0.113.7", UserAgent: "test-agent/1.0",
			Metadata: map[string]string{"method": "password"}, Timestamp: base},
		{Type: audit.EventPasswordChange, ActorID: userID, TargetID: userID, Timestamp: base.Add(time.Second)},
		{Type: audit.EventAdminUserLock, ActorID: "admin-1", TargetID: userID,
			Metadata: map[string]string{"reason": "test"}, Timestamp: base.Add(2 * time.Second)},
	}
	for _, ev := range events {
		svc.LogEvent(ctx, ev)
	}
	require.NoError(t, svc.Close())
	assert.Empty(t, drops.counts)

	// Rows carry every field, including the tenant resolved from the context.
	var (
		tenantID   uuid.UUID
		actor, ip  string
		userAgent  string
		metaMethod string
	)
	err = pool.QueryRow(ctx, `SELECT tenant_id, actor_id, ip, user_agent, metadata->>'method'
		FROM audit_logs WHERE target_id = $1 AND event_type = $2`, userID, audit.EventLoginSuccess).
		Scan(&tenantID, &actor, &ip, &userAgent, &metaMethod)
	require.NoError(t, err)
	assert.Equal(t, domain.DefaultTenantID, tenantID)
	assert.Equal(t, userID, actor)
	assert.Equal(t, "203.0.113.7", ip)
	assert.Equal(t, "test-agent/1.0", userAgent)
	assert.Equal(t, "password", metaMethod)

	// The admin user-audit endpoint's service layer returns them, newest first.
	userSvc := admin.NewUserService(storage.NewPostgresAdminUserRepository(pool), password.New([]byte("pepper")), zap.NewNop(), audit.NopLogger{})
	userSvc.SetAuditReadRepo(storage.NewPostgresAuditReadRepository(pool))

	timeline, err := userSvc.GetActivity(ctx, userID, 1, 10)
	require.NoError(t, err)
	assert.Equal(t, 3, timeline.Total)
	require.Len(t, timeline.Events, 3)
	assert.Equal(t, audit.EventAdminUserLock, timeline.Events[0].EventType)
	assert.Equal(t, "admin-1", timeline.Events[0].ActorID)
	assert.Equal(t, map[string]string{"reason": "test"}, timeline.Events[0].Metadata)
	assert.Equal(t, audit.EventPasswordChange, timeline.Events[1].EventType)
	assert.Equal(t, audit.EventLoginSuccess, timeline.Events[2].EventType)
	assert.Equal(t, "203.0.113.7", timeline.Events[2].IP)
	assert.True(t, base.Equal(timeline.Events[2].CreatedAt), "created_at comes from the event timestamp")
}

func TestPostgresAuditSink_InsertBatchIsAtomic(t *testing.T) {
	pool := testPool(t)
	createAuditLogsTable(t, pool)
	ctx := context.Background()
	sink := storage.NewPostgresAuditSink(pool)

	targetID := uuid.NewString()
	err := sink.InsertBatch(ctx, []audit.Event{
		{TenantID: domain.DefaultTenantID, Type: audit.EventLogout, TargetID: targetID, Timestamp: time.Now().UTC()},
		{TenantID: uuid.New(), Type: audit.EventLogout, TargetID: targetID, Timestamp: time.Now().UTC()}, // unknown tenant: FK violation
	})
	require.Error(t, err)

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE target_id = $1`, targetID).Scan(&n))
	assert.Equal(t, 0, n, "a failed batch stores nothing")

	require.NoError(t, sink.InsertBatch(ctx, nil))
}

func TestPostgresAuditSink_DeleteOlderThan(t *testing.T) {
	pool := testPool(t)
	createAuditLogsTable(t, pool)
	ctx := context.Background()
	sink := storage.NewPostgresAuditSink(pool)

	targetID := uuid.NewString()
	now := time.Now().UTC()
	require.NoError(t, sink.InsertBatch(ctx, []audit.Event{
		{TenantID: domain.DefaultTenantID, Type: audit.EventLogout, TargetID: targetID, Timestamp: now.AddDate(0, 0, -400)},
		{TenantID: domain.DefaultTenantID, Type: audit.EventLogout, TargetID: targetID, Timestamp: now.AddDate(0, 0, -10)},
	}))

	deleted, err := sink.DeleteOlderThan(ctx, now.AddDate(0, 0, -365))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, deleted, int64(1))

	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT COUNT(*) FROM audit_logs WHERE target_id = $1`, targetID).Scan(&n))
	assert.Equal(t, 1, n, "only the row inside the retention window remains")
}
