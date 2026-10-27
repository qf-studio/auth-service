package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/session"
)

const testSessionTTL = time.Hour

func newTestRedisClient(t *testing.T, mr *miniredis.Miniredis) *redis.Client {
	t.Helper()
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newRedisStore(t *testing.T) (*session.RedisStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	return session.NewRedisStore(newTestRedisClient(t, mr), testSessionTTL), mr
}

func newInfo(id, userID string, created time.Time) *api.SessionInfo {
	return &api.SessionInfo{
		ID:             id,
		UserID:         userID,
		IPAddress:      "203.0.113.7",
		UserAgent:      "TestAgent/1.0",
		CreatedAt:      created,
		LastActivityAt: created,
	}
}

func TestRedisStore_CreateAndList(t *testing.T) {
	store, _ := newRedisStore(t)
	ctx := context.Background()
	created := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", created)))

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "s1", got[0].ID)
	assert.Equal(t, "user-1", got[0].UserID)
	assert.Equal(t, "203.0.113.7", got[0].IPAddress)
	assert.Equal(t, "TestAgent/1.0", got[0].UserAgent)
	assert.True(t, created.Equal(got[0].CreatedAt))
}

func TestRedisStore_ListByUser_EmptyIsNonNil(t *testing.T) {
	store, _ := newRedisStore(t)

	got, err := store.ListByUser(context.Background(), "nobody")
	require.NoError(t, err)
	assert.NotNil(t, got)
	assert.Empty(t, got)
}

func TestRedisStore_ListByUser_OldestFirstAndPerUser(t *testing.T) {
	store, _ := newRedisStore(t)
	ctx := context.Background()
	base := time.Now().UTC()

	require.NoError(t, store.Create(ctx, newInfo("newer", "user-1", base.Add(time.Minute))))
	require.NoError(t, store.Create(ctx, newInfo("older", "user-1", base)))
	require.NoError(t, store.Create(ctx, newInfo("other", "user-2", base)))

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "older", got[0].ID)
	assert.Equal(t, "newer", got[1].ID)

	other, err := store.ListByUser(ctx, "user-2")
	require.NoError(t, err)
	require.Len(t, other, 1)
	assert.Equal(t, "other", other[0].ID)
}

func TestRedisStore_Delete(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", now)))
	require.NoError(t, store.Create(ctx, newInfo("s2", "user-1", now.Add(time.Second))))

	require.NoError(t, store.Delete(ctx, "user-1", "s1"))

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "s2", got[0].ID)

	// A second delete of the same session, an unknown session and another
	// user's session ID all report not-found.
	for _, tc := range []struct{ user, id string }{
		{"user-1", "s1"},
		{"user-1", "missing"},
		{"user-2", "s2"},
	} {
		err := store.Delete(ctx, tc.user, tc.id)
		assert.True(t, errors.Is(err, api.ErrNotFound), "%s/%s: %v", tc.user, tc.id, err)
	}

	still, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	assert.Len(t, still, 1, "failed deletes must not remove anything")
	assert.False(t, mr.Exists("session:user-1:s:s1"))
}

func TestRedisStore_DeleteAllForUser(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", now)))
	require.NoError(t, store.Create(ctx, newInfo("s2", "user-1", now)))
	require.NoError(t, store.Create(ctx, newInfo("s3", "user-2", now)))

	require.NoError(t, store.DeleteAllForUser(ctx, "user-1"))

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, got)
	assert.False(t, mr.Exists("session:user-1:idx"))
	assert.False(t, mr.Exists("session:user-1:s:s1"))

	other, err := store.ListByUser(ctx, "user-2")
	require.NoError(t, err)
	assert.Len(t, other, 1, "other users keep their sessions")

	// Idempotent for a user without sessions.
	require.NoError(t, store.DeleteAllForUser(ctx, "nobody"))
}

func TestRedisStore_Expiry(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", time.Now().UTC())))
	assert.Equal(t, testSessionTTL, mr.TTL("session:user-1:s:s1"))
	assert.Equal(t, testSessionTTL, mr.TTL("session:user-1:idx"))

	mr.FastForward(testSessionTTL + time.Second)

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, got, "expired sessions are not listed")
	assert.Empty(t, mr.Keys(), "nothing is left behind after expiry")
}

func TestRedisStore_ExpiryIsPerSession(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, newInfo("old", "user-1", time.Now().UTC())))
	mr.FastForward(testSessionTTL / 2)
	require.NoError(t, store.Create(ctx, newInfo("new", "user-1", time.Now().UTC())))
	mr.FastForward(testSessionTTL/2 + time.Second)

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 1, "a newer session must not extend an older one")
	assert.Equal(t, "new", got[0].ID)
}

func TestRedisStore_ListSkipsAndPrunesVanishedSession(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()

	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", time.Now().UTC())))
	require.NoError(t, store.Create(ctx, newInfo("s2", "user-1", time.Now().UTC().Add(time.Second))))
	mr.Del("session:user-1:s:s1") // record gone, index entry left behind

	got, err := store.ListByUser(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "s2", got[0].ID)

	members, err := mr.ZMembers("session:user-1:idx")
	require.NoError(t, err)
	assert.Equal(t, []string{"s2"}, members)
}

func TestRedisStore_TwoInstancesShareSessions(t *testing.T) {
	mr := miniredis.RunT(t)
	ctx := context.Background()
	// Two "tasks": separate clients, stores and services over one Redis.
	svcA := session.NewService(session.NewRedisStore(newTestRedisClient(t, mr), testSessionTTL))
	svcB := session.NewService(session.NewRedisStore(newTestRedisClient(t, mr), testSessionTTL))

	a, err := svcA.CreateSession(ctx, "user-1", "198.51.100.1", "A")
	require.NoError(t, err)
	b, err := svcB.CreateSession(ctx, "user-1", "198.51.100.2", "B")
	require.NoError(t, err)

	for name, svc := range map[string]*session.Service{"A": svcA, "B": svcB} {
		got, err := svc.ListSessions(ctx, "user-1")
		require.NoError(t, err, name)
		ids := make([]string, 0, len(got))
		for _, s := range got {
			ids = append(ids, s.ID)
		}
		assert.ElementsMatch(t, []string{a.ID, b.ID}, ids, "instance %s must see both sessions", name)
	}

	// A session created on one instance is terminable from the other.
	require.NoError(t, svcB.DeleteSession(ctx, "user-1", a.ID))
	got, err := svcA.ListSessions(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, b.ID, got[0].ID)

	require.NoError(t, svcA.DeleteAllSessions(ctx, "user-1"))
	got, err = svcB.ListSessions(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, got)
}

func TestRedisStore_RedisErrorsAreReturned(t *testing.T) {
	store, mr := newRedisStore(t)
	ctx := context.Background()
	require.NoError(t, store.Create(ctx, newInfo("s1", "user-1", time.Now().UTC())))

	mr.SetError("redis down")

	assert.Error(t, store.Create(ctx, newInfo("s2", "user-1", time.Now().UTC())))
	_, err := store.ListByUser(ctx, "user-1")
	assert.Error(t, err)
	assert.Error(t, store.Delete(ctx, "user-1", "s1"))
	assert.Error(t, store.DeleteAllForUser(ctx, "user-1"))
}
