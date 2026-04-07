package session_test

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
	"time"

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

// --- Table-driven tests ---

func TestService_CreateSession_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		userID    string
		ipAddress string
		userAgent string
	}{
		{
			name:      "full metadata",
			userID:    "user-full",
			ipAddress: "192.168.1.1",
			userAgent: "Mozilla/5.0",
		},
		{
			name:      "empty optional fields",
			userID:    "user-minimal",
			ipAddress: "",
			userAgent: "",
		},
		{
			name:      "ipv6 address",
			userID:    "user-ipv6",
			ipAddress: "::1",
			userAgent: "curl/7.88",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := session.NewMemoryStore()
			svc := session.NewService(store)
			ctx := context.Background()

			before := time.Now().UTC().Add(-time.Second)
			info, err := svc.CreateSession(ctx, tt.userID, tt.ipAddress, tt.userAgent)
			after := time.Now().UTC().Add(time.Second)

			require.NoError(t, err)
			require.NotNil(t, info)

			// Verify fields are set correctly.
			assert.Equal(t, tt.userID, info.UserID)
			assert.Equal(t, tt.ipAddress, info.IPAddress)
			assert.Equal(t, tt.userAgent, info.UserAgent)

			// Session ID must be 32 hex chars (16 bytes).
			assert.Len(t, info.ID, 32)
			_, err = hex.DecodeString(info.ID)
			assert.NoError(t, err, "session ID must be valid hex")

			// Timestamps must be within the test window.
			assert.True(t, info.CreatedAt.After(before), "CreatedAt too early")
			assert.True(t, info.CreatedAt.Before(after), "CreatedAt too late")
			assert.Equal(t, info.CreatedAt, info.LastActivityAt, "CreatedAt and LastActivityAt should match at creation")
		})
	}
}

func TestMemoryStore_Delete_TableDriven(t *testing.T) {
	tests := []struct {
		name        string
		setup       []api.SessionInfo // sessions to create
		deleteUser  string
		deleteID    string
		wantErr     bool
		wantErrIs   error
		wantRemain  int // remaining sessions for deleteUser
	}{
		{
			name: "delete first of two",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
				{ID: "s2", UserID: "u1"},
			},
			deleteUser: "u1",
			deleteID:   "s1",
			wantRemain: 1,
		},
		{
			name: "delete last session",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
			},
			deleteUser: "u1",
			deleteID:   "s1",
			wantRemain: 0,
		},
		{
			name:       "delete nonexistent session",
			setup:      []api.SessionInfo{},
			deleteUser: "u1",
			deleteID:   "ghost",
			wantErr:    true,
			wantErrIs:  api.ErrNotFound,
		},
		{
			name: "delete wrong user's session",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
			},
			deleteUser: "u2",
			deleteID:   "s1",
			wantErr:    true,
			wantErrIs:  api.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := session.NewMemoryStore()
			ctx := context.Background()

			for i := range tt.setup {
				require.NoError(t, store.Create(ctx, &tt.setup[i]))
			}

			err := store.Delete(ctx, tt.deleteUser, tt.deleteID)

			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					assert.True(t, errors.Is(err, tt.wantErrIs))
				}
				return
			}

			require.NoError(t, err)
			remaining, err := store.ListByUser(ctx, tt.deleteUser)
			require.NoError(t, err)
			assert.Len(t, remaining, tt.wantRemain)
		})
	}
}

func TestMemoryStore_ListByUser_TableDriven(t *testing.T) {
	tests := []struct {
		name      string
		setup     []api.SessionInfo
		queryUser string
		wantCount int
	}{
		{
			name:      "no sessions exist",
			setup:     nil,
			queryUser: "u1",
			wantCount: 0,
		},
		{
			name: "one session",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
			},
			queryUser: "u1",
			wantCount: 1,
		},
		{
			name: "multiple sessions same user",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
				{ID: "s2", UserID: "u1"},
				{ID: "s3", UserID: "u1"},
			},
			queryUser: "u1",
			wantCount: 3,
		},
		{
			name: "sessions for different user not returned",
			setup: []api.SessionInfo{
				{ID: "s1", UserID: "u1"},
				{ID: "s2", UserID: "u2"},
			},
			queryUser: "u1",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := session.NewMemoryStore()
			ctx := context.Background()

			for i := range tt.setup {
				require.NoError(t, store.Create(ctx, &tt.setup[i]))
			}

			sessions, err := store.ListByUser(ctx, tt.queryUser)
			require.NoError(t, err)
			assert.Len(t, sessions, tt.wantCount)
		})
	}
}

// --- Concurrent access safety ---

func TestMemoryStore_ConcurrentAccess(t *testing.T) {
	store := session.NewMemoryStore()
	ctx := context.Background()
	const goroutines = 50

	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Concurrent creates across multiple users.
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			userID := "user-1"
			if n%2 == 0 {
				userID = "user-2"
			}
			s := &api.SessionInfo{
				ID:     "sess-" + string(rune('A'+n)),
				UserID: userID,
			}
			_ = store.Create(ctx, s)
		}(i)
	}
	wg.Wait()

	// Verify no data loss — total sessions should equal goroutines.
	s1, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	s2, err := store.ListByUser(ctx, "user-2")
	require.NoError(t, err)
	assert.Equal(t, goroutines, len(s1)+len(s2))

	// Concurrent reads + deletes.
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			switch n % 3 {
			case 0:
				_, _ = store.ListByUser(ctx, "user-1")
			case 1:
				_, _ = store.ListByUser(ctx, "user-2")
			case 2:
				_ = store.DeleteAllForUser(ctx, "user-2")
			}
		}(i)
	}
	wg.Wait()
}

func TestService_ConcurrentCreateAndList(t *testing.T) {
	store := session.NewMemoryStore()
	svc := session.NewService(store)
	ctx := context.Background()
	const goroutines = 30

	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Half create, half list — simultaneously.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = svc.CreateSession(ctx, "user-race", "1.2.3.4", "Agent")
		}()
		go func() {
			defer wg.Done()
			_, _ = svc.ListSessions(ctx, "user-race")
		}()
	}
	wg.Wait()

	// All creates should have persisted.
	sessions, err := svc.ListSessions(ctx, "user-race")
	require.NoError(t, err)
	assert.Len(t, sessions, goroutines)
}
