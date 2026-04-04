package storage_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/storage"
)

// auditTestPool returns a pgxpool.Pool and creates the audit_logs table.
// Skips the test if TEST_DATABASE_URL is not set.
func auditTestPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	pool, err := pgxpool.New(ctx, dsn)
	require.NoError(t, err)

	t.Cleanup(func() { pool.Close() })

	createAuditTable(t, pool)

	return pool
}

func createAuditTable(t *testing.T, pool *pgxpool.Pool) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	_, err := pool.Exec(ctx, `
		DO $$ BEGIN
			CREATE TYPE audit_outcome AS ENUM ('success', 'failure', 'denied');
		EXCEPTION
			WHEN duplicate_object THEN NULL;
		END $$;

		CREATE TABLE IF NOT EXISTS audit_logs (
			id              TEXT            PRIMARY KEY,
			event_type      TEXT            NOT NULL,
			outcome         audit_outcome   NOT NULL,
			occurred_at     TIMESTAMPTZ     NOT NULL,
			subject_id      TEXT            NOT NULL DEFAULT '',
			subject_type    TEXT            NOT NULL DEFAULT '',
			resource_type   TEXT            NOT NULL DEFAULT '',
			resource_id     TEXT            NOT NULL DEFAULT '',
			action          TEXT            NOT NULL DEFAULT '',
			source_ip       TEXT            NOT NULL DEFAULT '',
			user_agent      TEXT            NOT NULL DEFAULT '',
			correlation_id  TEXT            NOT NULL DEFAULT '',
			component       TEXT            NOT NULL DEFAULT '',
			metadata        JSONB           NOT NULL DEFAULT '{}',
			created_at      TIMESTAMPTZ     NOT NULL DEFAULT now()
		);
	`)
	require.NoError(t, err)

	// Clean table for each test run.
	_, err = pool.Exec(ctx, "DELETE FROM audit_logs")
	require.NoError(t, err)
}

func makeTestEvent(eventType audit.EventType, outcome audit.Outcome) *audit.AuditEvent {
	return &audit.AuditEvent{
		ID:            uuid.New().String(),
		EventType:     eventType,
		Outcome:       outcome,
		Timestamp:     time.Now().UTC(),
		SubjectID:     "user-" + uuid.New().String()[:8],
		SubjectType:   "user",
		ResourceType:  "session",
		ResourceID:    "sess-" + uuid.New().String()[:8],
		Action:        "test action",
		SourceIP:      "127.0.0.1",
		UserAgent:     "test-agent/1.0",
		CorrelationID: "corr-" + uuid.New().String()[:8],
		Component:     "auth",
		Metadata:      map[string]string{"key": "value"},
	}
}

func TestPostgresAuditRepository_Insert(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
	err := repo.Insert(ctx, event)
	require.NoError(t, err)

	// Verify the event was stored.
	events, total, err := repo.List(ctx, storage.AuditFilter{Limit: 10})
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	require.Len(t, events, 1)
	assert.Equal(t, event.ID, events[0].ID)
	assert.Equal(t, event.EventType, events[0].EventType)
	assert.Equal(t, event.Outcome, events[0].Outcome)
	assert.Equal(t, event.SubjectID, events[0].SubjectID)
	assert.Equal(t, event.Component, events[0].Component)
	assert.Equal(t, "value", events[0].Metadata["key"])
}

func TestPostgresAuditRepository_Insert_DuplicateID(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
	err := repo.Insert(ctx, event)
	require.NoError(t, err)

	// Second insert with same ID should fail.
	err = repo.Insert(ctx, event)
	assert.Error(t, err)
}

func TestPostgresAuditRepository_Insert_NilMetadata(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
	event.Metadata = nil

	err := repo.Insert(ctx, event)
	require.NoError(t, err)
}

func TestPostgresAuditRepository_List_Pagination(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	// Insert 15 events with staggered timestamps.
	for i := 0; i < 15; i++ {
		event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
		event.Timestamp = time.Now().UTC().Add(time.Duration(i) * time.Second)
		err := repo.Insert(ctx, event)
		require.NoError(t, err)
	}

	// Page 1: first 5.
	events, total, err := repo.List(ctx, storage.AuditFilter{Limit: 5, Offset: 0})
	require.NoError(t, err)
	assert.Equal(t, 15, total)
	assert.Len(t, events, 5)

	// Page 2: next 5.
	events2, total2, err := repo.List(ctx, storage.AuditFilter{Limit: 5, Offset: 5})
	require.NoError(t, err)
	assert.Equal(t, 15, total2)
	assert.Len(t, events2, 5)

	// Events should be ordered descending by occurred_at.
	assert.True(t, events[0].Timestamp.After(events[4].Timestamp) || events[0].Timestamp.Equal(events[4].Timestamp))
}

func TestPostgresAuditRepository_List_FilterByEventType(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	// Insert mixed event types.
	for i := 0; i < 5; i++ {
		err := repo.Insert(ctx, makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess))
		require.NoError(t, err)
	}
	for i := 0; i < 3; i++ {
		err := repo.Insert(ctx, makeTestEvent(audit.EventLoginFailure, audit.OutcomeFailure))
		require.NoError(t, err)
	}

	events, total, err := repo.List(ctx, storage.AuditFilter{
		EventType: string(audit.EventLoginFailure),
		Limit:     50,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, events, 3)
	for _, e := range events {
		assert.Equal(t, audit.EventLoginFailure, e.EventType)
	}
}

func TestPostgresAuditRepository_List_FilterBySubjectID(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	targetSubject := "user-target"
	for i := 0; i < 3; i++ {
		event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
		event.SubjectID = targetSubject
		err := repo.Insert(ctx, event)
		require.NoError(t, err)
	}
	for i := 0; i < 5; i++ {
		err := repo.Insert(ctx, makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess))
		require.NoError(t, err)
	}

	events, total, err := repo.List(ctx, storage.AuditFilter{
		SubjectID: targetSubject,
		Limit:     50,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, events, 3)
}

func TestPostgresAuditRepository_List_FilterByTimeRange(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	baseTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	for i := 0; i < 10; i++ {
		event := makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess)
		event.Timestamp = baseTime.Add(time.Duration(i) * time.Hour)
		err := repo.Insert(ctx, event)
		require.NoError(t, err)
	}

	// Filter: hours 3-6 (indices 3, 4, 5).
	events, total, err := repo.List(ctx, storage.AuditFilter{
		From:  baseTime.Add(3 * time.Hour),
		To:    baseTime.Add(6 * time.Hour),
		Limit: 50,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, events, 3)
}

func TestPostgresAuditRepository_List_DefaultAndMaxLimit(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	// Insert 5 events.
	for i := 0; i < 5; i++ {
		err := repo.Insert(ctx, makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess))
		require.NoError(t, err)
	}

	// Default limit (0 -> 50).
	events, _, err := repo.List(ctx, storage.AuditFilter{})
	require.NoError(t, err)
	assert.Len(t, events, 5) // Less than default 50.

	// Excessive limit gets capped to 200.
	events, _, err = repo.List(ctx, storage.AuditFilter{Limit: 999})
	require.NoError(t, err)
	assert.Len(t, events, 5)
}

func TestPostgresAuditRepository_List_FilterByResource(t *testing.T) {
	pool := auditTestPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		event := makeTestEvent(audit.EventUserUpdate, audit.OutcomeSuccess)
		event.ResourceType = "user"
		event.ResourceID = "user-target"
		err := repo.Insert(ctx, event)
		require.NoError(t, err)
	}
	for i := 0; i < 2; i++ {
		err := repo.Insert(ctx, makeTestEvent(audit.EventLoginSuccess, audit.OutcomeSuccess))
		require.NoError(t, err)
	}

	events, total, err := repo.List(ctx, storage.AuditFilter{
		ResourceType: "user",
		ResourceID:   "user-target",
		Limit:        50,
	})
	require.NoError(t, err)
	assert.Equal(t, 3, total)
	assert.Len(t, events, 3)
}
