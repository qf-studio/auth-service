package session_test

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/session"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- MemoryStore tests ---

func TestMemoryStore_Create(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	s := &api.SessionInfo{
		ID:        "sess-1",
		UserID:    "user-1",
		IPAddress: "127.0.0.1",
		UserAgent: "TestAgent/1.0",
	}

	err := store.Create(ctx, s)
	require.NoError(t, err)

	sessions, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "sess-1", sessions[0].ID)
}

func TestMemoryStore_ListByUser_Empty(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	sessions, err := store.ListByUser(ctx, "nonexistent-user")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestMemoryStore_ListByUser_MultipleUsers(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	_ = store.Create(ctx, &api.SessionInfo{ID: "a1", UserID: "user-a"})
	_ = store.Create(ctx, &api.SessionInfo{ID: "a2", UserID: "user-a"})
	_ = store.Create(ctx, &api.SessionInfo{ID: "b1", UserID: "user-b"})

	sessA, err := store.ListByUser(ctx, "user-a")
	require.NoError(t, err)
	assert.Len(t, sessA, 2)

	sessB, err := store.ListByUser(ctx, "user-b")
	require.NoError(t, err)
	assert.Len(t, sessB, 1)
}

func TestMemoryStore_ListByUser_ReturnsCopy(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	_ = store.Create(ctx, &api.SessionInfo{ID: "sess-1", UserID: "user-1"})

	results, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)

	// Mutating the returned slice should not affect the store.
	results[0].IPAddress = "mutated"

	results2, _ := store.ListByUser(ctx, "user-1")
	assert.Empty(t, results2[0].IPAddress)
}

func TestMemoryStore_Delete_Found(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	_ = store.Create(ctx, &api.SessionInfo{ID: "sess-1", UserID: "user-1"})
	_ = store.Create(ctx, &api.SessionInfo{ID: "sess-2", UserID: "user-1"})

	err := store.Delete(ctx, "user-1", "sess-1")
	require.NoError(t, err)

	sessions, _ := store.ListByUser(ctx, "user-1")
	require.Len(t, sessions, 1)
	assert.Equal(t, "sess-2", sessions[0].ID)
}

func TestMemoryStore_Delete_NotFound(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	err := store.Delete(ctx, "user-1", "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestMemoryStore_DeleteAllForUser(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	_ = store.Create(ctx, &api.SessionInfo{ID: "sess-1", UserID: "user-1"})
	_ = store.Create(ctx, &api.SessionInfo{ID: "sess-2", UserID: "user-1"})

	err := store.DeleteAllForUser(ctx, "user-1")
	require.NoError(t, err)

	sessions, _ := store.ListByUser(ctx, "user-1")
	assert.Empty(t, sessions)
}

func TestMemoryStore_DeleteAllForUser_NonexistentUser(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	// Should not error when user has no sessions.
	err := store.DeleteAllForUser(ctx, "ghost-user")
	require.NoError(t, err)
}

// --- Service tests (backed by MemoryStore) ---

func TestService_CreateSession(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	info, err := svc.CreateSession(ctx, "user-1", "10.0.0.1", "Mozilla/5.0")
	require.NoError(t, err)
	require.NotNil(t, info)

	assert.NotEmpty(t, info.ID)
	assert.Equal(t, "user-1", info.UserID)
	assert.Equal(t, "10.0.0.1", info.IPAddress)
	assert.Equal(t, "Mozilla/5.0", info.UserAgent)
	assert.False(t, info.CreatedAt.IsZero())
	assert.False(t, info.LastActivityAt.IsZero())
}

func TestService_CreateSession_UniqueIDs(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	info1, err := svc.CreateSession(ctx, "user-1", "", "")
	require.NoError(t, err)

	info2, err := svc.CreateSession(ctx, "user-1", "", "")
	require.NoError(t, err)

	assert.NotEqual(t, info1.ID, info2.ID)
}

func TestService_ListSessions(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	_, _ = svc.CreateSession(ctx, "user-1", "1.2.3.4", "AgentA")
	_, _ = svc.CreateSession(ctx, "user-1", "5.6.7.8", "AgentB")

	sessions, err := svc.ListSessions(ctx, "user-1")
	require.NoError(t, err)
	assert.Len(t, sessions, 2)
}

func TestService_ListSessions_Empty(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	sessions, err := svc.ListSessions(ctx, "no-such-user")
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestService_DeleteSession(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	info, _ := svc.CreateSession(ctx, "user-1", "", "")

	err := svc.DeleteSession(ctx, "user-1", info.ID)
	require.NoError(t, err)

	sessions, _ := svc.ListSessions(ctx, "user-1")
	assert.Empty(t, sessions)
}

func TestService_DeleteSession_NotFound(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	err := svc.DeleteSession(ctx, "user-1", "nonexistent")
	require.Error(t, err)
	assert.True(t, errors.Is(err, api.ErrNotFound))
}

func TestService_DeleteAllSessions(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()

	_, _ = svc.CreateSession(ctx, "user-1", "", "")
	_, _ = svc.CreateSession(ctx, "user-1", "", "")

	err := svc.DeleteAllSessions(ctx, "user-1")
	require.NoError(t, err)

	sessions, _ := svc.ListSessions(ctx, "user-1")
	assert.Empty(t, sessions)
}

// --- Concurrent access safety ---

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()

	const goroutines = 20
	done := make(chan struct{})

	// Writers: create sessions concurrently.
	for i := range goroutines {
		go func(i int) {
			defer func() { done <- struct{}{} }()
			_ = store.Create(ctx, &api.SessionInfo{
				ID:     fmt.Sprintf("sess-%d", i),
				UserID: "shared-user",
			})
		}(i)
	}

	// Readers: list sessions concurrently.
	for range goroutines {
		go func() {
			defer func() { done <- struct{}{} }()
			_, _ = store.ListByUser(ctx, "shared-user")
		}()
	}

	for range goroutines * 2 {
		<-done
	}

	// All goroutines completed without data race — verified by -race flag.
	sessions, err := store.ListByUser(ctx, "shared-user")
	require.NoError(t, err)
	assert.Len(t, sessions, goroutines)
}

// --- Error propagation tests using a failing store ---

type failStore struct{ err error }

func (f *failStore) Create(_ context.Context, _ *api.SessionInfo) error              { return f.err }
func (f *failStore) ListByUser(_ context.Context, _ string) ([]api.SessionInfo, error) {
	return nil, f.err
}
func (f *failStore) Delete(_ context.Context, _, _ string) error        { return f.err }
func (f *failStore) DeleteAllForUser(_ context.Context, _ string) error { return f.err }

func TestService_CreateSession_StoreError(t *testing.T) {
	sentinel := errors.New("store failure")
	svc := session.NewService(&failStore{err: sentinel})

	_, err := svc.CreateSession(context.Background(), "u", "ip", "ua")
	require.Error(t, err)
	assert.True(t, errors.Is(err, sentinel))
}

func TestService_ListSessions_StoreError(t *testing.T) {
	sentinel := errors.New("store failure")
	svc := session.NewService(&failStore{err: sentinel})

	_, err := svc.ListSessions(context.Background(), "u")
	require.Error(t, err)
	assert.True(t, errors.Is(err, sentinel))
}

func TestService_DeleteSession_StoreError(t *testing.T) {
	sentinel := errors.New("store failure")
	svc := session.NewService(&failStore{err: sentinel})

	err := svc.DeleteSession(context.Background(), "u", "s")
	require.Error(t, err)
	assert.True(t, errors.Is(err, sentinel))
}

func TestService_DeleteAllSessions_StoreError(t *testing.T) {
	sentinel := errors.New("store failure")
	svc := session.NewService(&failStore{err: sentinel})

	err := svc.DeleteAllSessions(context.Background(), "u")
	require.Error(t, err)
	assert.True(t, errors.Is(err, sentinel))
}
