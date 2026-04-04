package session_test

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/session"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func testLogger() *zap.Logger {
	return zap.NewNop()
}

func newTestService(t *testing.T) (*session.Service, *miniredis.Miniredis) {
	t.Helper()
	mr, rc := newTestRedis(t)
	svc := session.NewService(rc, testLogger())
	return svc, mr
}

func newSession(userID string) *domain.Session {
	return &domain.Session{
		UserID:            userID,
		DeviceFingerprint: "fp-abc123",
		IP:                "192.168.1.1",
		UserAgent:         "Mozilla/5.0 (test)",
		RefreshTokenJTI:   "jti-xyz789",
	}
}

// ── CreateSession ────────────────────────────────────────────────────────────

func TestCreateSession(t *testing.T) {
	tests := []struct {
		name    string
		session *domain.Session
	}{
		{
			name:    "creates session with generated ID",
			session: newSession("user-1"),
		},
		{
			name: "creates session with provided ID",
			session: &domain.Session{
				ID:                "custom-id",
				UserID:            "user-2",
				DeviceFingerprint: "fp-def456",
				IP:                "10.0.0.1",
				UserAgent:         "curl/7.68",
				RefreshTokenJTI:   "jti-abc",
			},
		},
		{
			name: "creates session with minimal fields",
			session: &domain.Session{
				UserID: "user-3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			ctx := context.Background()

			result, err := svc.CreateSession(ctx, tt.session)
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.NotEmpty(t, result.ID)
			assert.Equal(t, tt.session.UserID, result.UserID)
			assert.False(t, result.CreatedAt.IsZero())
			assert.False(t, result.LastActivityAt.IsZero())
			assert.Equal(t, result.CreatedAt, result.LastActivityAt)

			if tt.session.ID != "" {
				assert.Equal(t, tt.session.ID, result.ID)
			}
		})
	}
}

func TestCreateSession_Retrievable(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.CreateSession(ctx, newSession("user-1"))
	require.NoError(t, err)

	got, err := svc.GetSession(ctx, created.ID)
	require.NoError(t, err)

	assert.Equal(t, created.ID, got.ID)
	assert.Equal(t, created.UserID, got.UserID)
	assert.Equal(t, created.DeviceFingerprint, got.DeviceFingerprint)
	assert.Equal(t, created.IP, got.IP)
	assert.Equal(t, created.UserAgent, got.UserAgent)
	assert.Equal(t, created.RefreshTokenJTI, got.RefreshTokenJTI)
}

// ── GetSession ───────────────────────────────────────────────────────────────

func TestGetSession_NotFound(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	_, err := svc.GetSession(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrSessionNotFound)
}

func TestGetSession_Expired(t *testing.T) {
	svc, mr := newTestService(t)
	ctx := context.Background()

	created, err := svc.CreateSession(ctx, newSession("user-1"))
	require.NoError(t, err)

	// Fast-forward past the 24h TTL.
	mr.FastForward(25 * time.Hour)

	_, err = svc.GetSession(ctx, created.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrSessionNotFound)
}

// ── ListSessions ─────────────────────────────────────────────────────────────

func TestListSessions(t *testing.T) {
	tests := []struct {
		name          string
		setupCount    int
		expectedCount int
	}{
		{
			name:          "no sessions returns empty slice",
			setupCount:    0,
			expectedCount: 0,
		},
		{
			name:          "single session",
			setupCount:    1,
			expectedCount: 1,
		},
		{
			name:          "multiple sessions",
			setupCount:    3,
			expectedCount: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _ := newTestService(t)
			ctx := context.Background()
			userID := "user-list"

			for i := 0; i < tt.setupCount; i++ {
				sess := newSession(userID)
				sess.IP = "10.0.0." + string(rune('1'+i))
				_, err := svc.CreateSession(ctx, sess)
				require.NoError(t, err)
			}

			sessions, err := svc.ListSessions(ctx, userID)
			require.NoError(t, err)
			assert.Len(t, sessions, tt.expectedCount)
		})
	}
}

func TestListSessions_OnlyReturnsUserSessions(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Create sessions for two different users.
	for i := 0; i < 3; i++ {
		_, err := svc.CreateSession(ctx, newSession("user-A"))
		require.NoError(t, err)
	}
	for i := 0; i < 2; i++ {
		_, err := svc.CreateSession(ctx, newSession("user-B"))
		require.NoError(t, err)
	}

	sessionsA, err := svc.ListSessions(ctx, "user-A")
	require.NoError(t, err)
	assert.Len(t, sessionsA, 3)

	sessionsB, err := svc.ListSessions(ctx, "user-B")
	require.NoError(t, err)
	assert.Len(t, sessionsB, 2)
}

func TestListSessions_CleansExpiredReferences(t *testing.T) {
	svc, mr := newTestService(t)
	ctx := context.Background()
	userID := "user-cleanup"

	// Create a session.
	created, err := svc.CreateSession(ctx, newSession(userID))
	require.NoError(t, err)

	// Expire the session key directly but leave the user set entry.
	mr.FastForward(25 * time.Hour)

	// Create a fresh session (user set still has stale + new entry).
	fresh := newSession(userID)
	_, err = svc.CreateSession(ctx, fresh)
	require.NoError(t, err)

	// ListSessions should return only the fresh session and clean up the stale ref.
	sessions, err := svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.NotEqual(t, created.ID, sessions[0].ID)
}

// ── UpdateActivity ───────────────────────────────────────────────────────────

func TestUpdateActivity(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	created, err := svc.CreateSession(ctx, newSession("user-1"))
	require.NoError(t, err)

	// Wait a tiny bit to ensure time difference.
	time.Sleep(5 * time.Millisecond)

	err = svc.UpdateActivity(ctx, created.ID)
	require.NoError(t, err)

	updated, err := svc.GetSession(ctx, created.ID)
	require.NoError(t, err)

	assert.True(t, updated.LastActivityAt.After(created.LastActivityAt),
		"last_activity_at should be updated")
	assert.True(t, created.CreatedAt.Equal(updated.CreatedAt),
		"created_at should not change")
}

func TestUpdateActivity_NotFound(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	err := svc.UpdateActivity(ctx, "nonexistent-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrSessionNotFound)
}

func TestUpdateActivity_ResetsTTL(t *testing.T) {
	svc, mr := newTestService(t)
	ctx := context.Background()

	created, err := svc.CreateSession(ctx, newSession("user-1"))
	require.NoError(t, err)

	// Advance 23 hours (nearly expired).
	mr.FastForward(23 * time.Hour)

	// Update activity should reset TTL.
	err = svc.UpdateActivity(ctx, created.ID)
	require.NoError(t, err)

	// Advance another 23 hours (would be 46h total, but TTL was reset).
	mr.FastForward(23 * time.Hour)

	// Session should still be accessible.
	got, err := svc.GetSession(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, got.ID)
}

// ── RevokeSession ────────────────────────────────────────────────────────────

func TestRevokeSession(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	userID := "user-1"

	created, err := svc.CreateSession(ctx, newSession(userID))
	require.NoError(t, err)

	err = svc.RevokeSession(ctx, userID, created.ID)
	require.NoError(t, err)

	// Session should no longer be retrievable.
	_, err = svc.GetSession(ctx, created.ID)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrSessionNotFound)

	// Should not appear in user's session list.
	sessions, err := svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestRevokeSession_DoesNotAffectOtherSessions(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	userID := "user-1"

	sess1, err := svc.CreateSession(ctx, newSession(userID))
	require.NoError(t, err)

	sess2, err := svc.CreateSession(ctx, newSession(userID))
	require.NoError(t, err)

	// Revoke only the first session.
	err = svc.RevokeSession(ctx, userID, sess1.ID)
	require.NoError(t, err)

	// Second session should still exist.
	got, err := svc.GetSession(ctx, sess2.ID)
	require.NoError(t, err)
	assert.Equal(t, sess2.ID, got.ID)

	sessions, err := svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
}

func TestRevokeSession_NonexistentIsIdempotent(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Revoking a nonexistent session should not error.
	err := svc.RevokeSession(ctx, "user-1", "nonexistent-id")
	require.NoError(t, err)
}

// ── RevokeAllSessions ────────────────────────────────────────────────────────

func TestRevokeAllSessions(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	userID := "user-1"

	// Create multiple sessions.
	for i := 0; i < 5; i++ {
		_, err := svc.CreateSession(ctx, newSession(userID))
		require.NoError(t, err)
	}

	sessions, err := svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 5)

	// Revoke all.
	err = svc.RevokeAllSessions(ctx, userID)
	require.NoError(t, err)

	// All should be gone.
	sessions, err = svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}

func TestRevokeAllSessions_DoesNotAffectOtherUsers(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := svc.CreateSession(ctx, newSession("user-A"))
		require.NoError(t, err)
	}
	_, err := svc.CreateSession(ctx, newSession("user-B"))
	require.NoError(t, err)

	// Revoke all for user-A.
	err = svc.RevokeAllSessions(ctx, "user-A")
	require.NoError(t, err)

	// user-B should be unaffected.
	sessions, err := svc.ListSessions(ctx, "user-B")
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
}

func TestRevokeAllSessions_NoSessionsIsNoop(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	err := svc.RevokeAllSessions(ctx, "user-no-sessions")
	require.NoError(t, err)
}

// ── End-to-end ───────────────────────────────────────────────────────────────

func TestEndToEnd_FullSessionLifecycle(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()
	userID := "user-e2e"

	// 1. Create session.
	created, err := svc.CreateSession(ctx, &domain.Session{
		UserID:            userID,
		DeviceFingerprint: "fp-e2e",
		IP:                "203.0.113.1",
		UserAgent:         "TestBrowser/1.0",
		RefreshTokenJTI:   "jti-e2e",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, created.ID)

	// 2. Get session.
	got, err := svc.GetSession(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, userID, got.UserID)
	assert.Equal(t, "fp-e2e", got.DeviceFingerprint)
	assert.Equal(t, "203.0.113.1", got.IP)
	assert.Equal(t, "TestBrowser/1.0", got.UserAgent)
	assert.Equal(t, "jti-e2e", got.RefreshTokenJTI)

	// 3. List sessions.
	sessions, err := svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)

	// 4. Update activity.
	time.Sleep(5 * time.Millisecond)
	err = svc.UpdateActivity(ctx, created.ID)
	require.NoError(t, err)

	updated, err := svc.GetSession(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, updated.LastActivityAt.After(created.LastActivityAt))

	// 5. Create a second session.
	sess2, err := svc.CreateSession(ctx, &domain.Session{
		UserID:          userID,
		IP:              "198.51.100.1",
		UserAgent:       "MobileApp/2.0",
		RefreshTokenJTI: "jti-mobile",
	})
	require.NoError(t, err)

	sessions, err = svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 2)

	// 6. Revoke first session.
	err = svc.RevokeSession(ctx, userID, created.ID)
	require.NoError(t, err)

	sessions, err = svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 1)
	assert.Equal(t, sess2.ID, sessions[0].ID)

	// 7. Revoke all remaining.
	err = svc.RevokeAllSessions(ctx, userID)
	require.NoError(t, err)

	sessions, err = svc.ListSessions(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, sessions, 0)
}
