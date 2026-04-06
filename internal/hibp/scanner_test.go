package hibp

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

// scannerUserRepo implements storage.UserRepository for scanner tests.
type scannerUserRepo struct {
	setForcePasswordChangeFn func(ctx context.Context, userID string, force bool) error
	listActiveUserIDsFn      func(ctx context.Context, limit, offset int) ([]string, error)
}

func (m *scannerUserRepo) Create(_ context.Context, _ *domain.User) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *scannerUserRepo) FindByID(_ context.Context, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *scannerUserRepo) FindByEmail(_ context.Context, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *scannerUserRepo) UpdateLastLogin(_ context.Context, _ string, _ time.Time) error {
	return nil
}
func (m *scannerUserRepo) SetEmailVerifyToken(_ context.Context, _, _ string, _ time.Time) error {
	return nil
}
func (m *scannerUserRepo) ConsumeEmailVerifyToken(_ context.Context, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}
func (m *scannerUserRepo) SetForcePasswordChange(ctx context.Context, userID string, force bool) error {
	if m.setForcePasswordChangeFn != nil {
		return m.setForcePasswordChangeFn(ctx, userID, force)
	}
	return nil
}
func (m *scannerUserRepo) ListActiveUserIDs(ctx context.Context, limit, offset int) ([]string, error) {
	if m.listActiveUserIDsFn != nil {
		return m.listActiveUserIDsFn(ctx, limit, offset)
	}
	return nil, nil
}

func TestCachePasswordHash(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = client.Close() }()

	ctx := context.Background()
	err = CachePasswordHash(ctx, client, "user-1", "password")
	require.NoError(t, err)

	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	val, err := client.Get(ctx, sha1CachePrefix+"user-1").Result()
	require.NoError(t, err)
	assert.Equal(t, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8", val)

	ttl := mr.TTL(sha1CachePrefix + "user-1")
	assert.True(t, ttl > 0, "expected TTL to be set")
}

func TestScanner_FlagsCompromisedUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// SHA-1("password") prefix = 5BAA6
		if r.URL.Path == "/range/5BAA6" {
			_, _ = w.Write([]byte("1E4C9B93F3F0682250B6CF8331B7EE68FD8:10000000\r\n"))
		} else {
			_, _ = w.Write([]byte("0000000000000000000000000000000000000:0\r\n"))
		}
	}))
	defer srv.Close()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = redisClient.Close() }()

	ctx := context.Background()

	// Cache the SHA-1 hash for user-1 (as if they logged in with "password").
	err = CachePasswordHash(ctx, redisClient, "user-1", "password")
	require.NoError(t, err)

	var flaggedUserID string
	var flaggedForce bool
	repo := &scannerUserRepo{
		listActiveUserIDsFn: func(_ context.Context, _, _ int) ([]string, error) {
			return []string{"user-1"}, nil
		},
		setForcePasswordChangeFn: func(_ context.Context, userID string, force bool) error {
			flaggedUserID = userID
			flaggedForce = force
			return nil
		},
	}

	logger, _ := zap.NewDevelopment()
	hibpClient := NewClient(srv.Client(), srv.URL+"/range/")

	scanner := NewScanner(hibpClient, repo, redisClient, logger, audit.NopLogger{}, 1*time.Hour)
	scanner.scan(ctx)

	assert.Equal(t, "user-1", flaggedUserID, "expected user-1 to be flagged")
	assert.True(t, flaggedForce, "expected force_password_change to be true")

	// Cache entry should be deleted after flagging.
	_, err = redisClient.Get(ctx, sha1CachePrefix+"user-1").Result()
	assert.ErrorIs(t, err, redis.Nil, "cache should be cleared after flagging")
}

func TestScanner_SkipsCleanUser(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0000000000000000000000000000000000000:0\r\n"))
	}))
	defer srv.Close()

	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = redisClient.Close() }()

	ctx := context.Background()
	err = CachePasswordHash(ctx, redisClient, "user-2", "strongpassword123")
	require.NoError(t, err)

	var flagged bool
	repo := &scannerUserRepo{
		listActiveUserIDsFn: func(_ context.Context, _, _ int) ([]string, error) {
			return []string{"user-2"}, nil
		},
		setForcePasswordChangeFn: func(_ context.Context, _ string, _ bool) error {
			flagged = true
			return nil
		},
	}

	logger, _ := zap.NewDevelopment()
	hibpClient := NewClient(srv.Client(), srv.URL+"/range/")

	scanner := NewScanner(hibpClient, repo, redisClient, logger, audit.NopLogger{}, 1*time.Hour)
	scanner.scan(ctx)

	assert.False(t, flagged, "clean user should not be flagged")
}

func TestScanner_StartAndStop(t *testing.T) {
	mr, err := miniredis.Run()
	require.NoError(t, err)
	defer mr.Close()

	redisClient := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	defer func() { _ = redisClient.Close() }()

	repo := &scannerUserRepo{
		listActiveUserIDsFn: func(_ context.Context, _, _ int) ([]string, error) {
			return nil, nil
		},
	}

	logger, _ := zap.NewDevelopment()

	scanner := NewScanner(NopChecker{}, repo, redisClient, logger, audit.NopLogger{}, 100*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	scanner.Start(ctx)

	// Let it run a tick.
	time.Sleep(150 * time.Millisecond)

	cancel()

	select {
	case <-scanner.Done():
		// Scanner stopped cleanly.
	case <-time.After(2 * time.Second):
		t.Fatal("scanner did not stop within timeout")
	}
}

func TestNopChecker(t *testing.T) {
	breached, err := NopChecker{}.IsBreached(context.Background(), "anything")
	require.NoError(t, err)
	assert.False(t, breached)
}
