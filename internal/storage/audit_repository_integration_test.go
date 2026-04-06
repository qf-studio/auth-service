package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

func TestPostgresAuditRepository_Create(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	entry := &domain.AuditLog{
		EventType: "login_success",
		ActorID:   "user-1",
		TargetID:  "session-1",
		IP:        "10.0.0.1",
		Metadata:  map[string]string{"browser": "chrome"},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}

	err := repo.Create(ctx, entry)
	require.NoError(t, err)
}

func TestPostgresAuditRepository_FindByID(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	entry := &domain.AuditLog{
		EventType: "register",
		ActorID:   "user-2",
		TargetID:  "user-2",
		IP:        "192.168.1.1",
		Metadata:  map[string]string{"method": "email"},
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	require.NoError(t, repo.Create(ctx, entry))

	// List to get the generated ID.
	logs, total, err := repo.List(ctx, 10, 0, "user-2", "", "")
	require.NoError(t, err)
	require.Equal(t, 1, total)
	require.Len(t, logs, 1)

	found, err := repo.FindByID(ctx, logs[0].ID)
	require.NoError(t, err)
	assert.Equal(t, "register", found.EventType)
	assert.Equal(t, "user-2", found.ActorID)
	assert.Equal(t, "192.168.1.1", found.IP)
	assert.Equal(t, "email", found.Metadata["method"])
}

func TestPostgresAuditRepository_FindByID_NotFound(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	_, err := repo.FindByID(ctx, uuid.New())
	require.ErrorIs(t, err, storage.ErrNotFound)
}

func TestPostgresAuditRepository_List_Filters(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	entries := []*domain.AuditLog{
		{EventType: "login_success", ActorID: "actor-a", TargetID: "target-1", CreatedAt: now},
		{EventType: "login_failure", ActorID: "actor-a", TargetID: "target-2", CreatedAt: now.Add(time.Second)},
		{EventType: "login_success", ActorID: "actor-b", TargetID: "target-1", CreatedAt: now.Add(2 * time.Second)},
	}
	for _, e := range entries {
		require.NoError(t, repo.Create(ctx, e))
	}

	// Filter by actor.
	logs, total, err := repo.List(ctx, 10, 0, "actor-a", "", "")
	require.NoError(t, err)
	assert.Equal(t, 2, total)
	assert.Len(t, logs, 2)

	// Filter by event type.
	logs, total, err = repo.List(ctx, 10, 0, "", "", "login_success")
	require.NoError(t, err)
	assert.GreaterOrEqual(t, total, 2)
	for _, l := range logs {
		assert.Equal(t, "login_success", l.EventType)
	}

	// Filter by target.
	logs, total, err = repo.List(ctx, 10, 0, "", "target-2", "")
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Equal(t, "actor-a", logs[0].ActorID)
}

func TestPostgresAuditRepository_List_Pagination(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	actor := uuid.New().String() // unique actor to isolate this test
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i := 0; i < 5; i++ {
		require.NoError(t, repo.Create(ctx, &domain.AuditLog{
			EventType: "token_refresh",
			ActorID:   actor,
			CreatedAt: now.Add(time.Duration(i) * time.Second),
		}))
	}

	// Page 1.
	logs, total, err := repo.List(ctx, 2, 0, actor, "", "")
	require.NoError(t, err)
	assert.Equal(t, 5, total)
	assert.Len(t, logs, 2)

	// Page 2.
	logs, _, err = repo.List(ctx, 2, 2, actor, "", "")
	require.NoError(t, err)
	assert.Len(t, logs, 2)

	// Page 3 (last item).
	logs, _, err = repo.List(ctx, 2, 4, actor, "", "")
	require.NoError(t, err)
	assert.Len(t, logs, 1)
}

func TestPostgresAuditRepository_Create_NilMetadata(t *testing.T) {
	pool := testPool(t)
	repo := storage.NewPostgresAuditRepository(pool)
	ctx := context.Background()

	entry := &domain.AuditLog{
		EventType: "logout",
		ActorID:   "user-nil-meta",
		CreatedAt: time.Now().UTC().Truncate(time.Microsecond),
	}
	require.NoError(t, repo.Create(ctx, entry))

	logs, _, err := repo.List(ctx, 1, 0, "user-nil-meta", "", "")
	require.NoError(t, err)
	require.Len(t, logs, 1)
	// nil metadata should come back as nil or empty map, not cause an error.
	assert.True(t, len(logs[0].Metadata) == 0)
}
