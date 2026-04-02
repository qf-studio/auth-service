package auth

import (
	"context"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
)

// newTestService creates a Service with a real Redis client for integration tests.
// Tests that call this are skipped when Redis is unavailable.
func newTestService(t *testing.T) *Service {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15, // use dedicated test DB
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("redis unavailable, skipping integration test: %v", err)
	}

	// Flush test DB before each test.
	_, err := client.FlushDB(ctx).Result()
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = client.FlushDB(context.Background()).Result()
		_ = client.Close()
	})

	logger, _ := zap.NewDevelopment()
	return NewService(client, logger)
}

func TestResetPassword_StoresTokenInRedis(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "user@example.com")
	require.NoError(t, err)

	// Verify a token was stored with the correct email.
	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1, "expected exactly one reset token in Redis")

	email, err := svc.redis.Get(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", email)

	// Verify TTL is set.
	ttl, err := svc.redis.TTL(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.True(t, ttl > 0 && ttl <= resetTokenTTL, "expected TTL in (0, %v], got %v", resetTokenTTL, ttl)
}

func TestConfirmPasswordReset_ValidToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Manually store a reset token.
	token := "test-reset-token-abc123"
	key := resetTokenPrefix + token
	err := svc.redis.Set(ctx, key, "user@example.com", resetTokenTTL).Err()
	require.NoError(t, err)

	// Confirm should succeed and delete the token.
	err = svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	// Token should be gone from Redis.
	exists, err := svc.redis.Exists(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "token should be deleted after confirmation")
}

func TestConfirmPasswordReset_InvalidToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.ConfirmPasswordReset(ctx, "nonexistent-token", "new-secure-password-12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestConfirmPasswordReset_TokenUsedOnce(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	token := "one-time-token"
	key := resetTokenPrefix + token
	err := svc.redis.Set(ctx, key, "user@example.com", resetTokenTTL).Err()
	require.NoError(t, err)

	// First use succeeds.
	err = svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	// Second use fails — token consumed.
	err = svc.ConfirmPasswordReset(ctx, token, "another-password-67890")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestResetPassword_FullFlow(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Step 1: Request reset.
	err := svc.ResetPassword(ctx, "alice@example.com")
	require.NoError(t, err)

	// Step 2: Extract the token from Redis.
	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	// Extract token from key by removing prefix.
	token := keys[0][len(resetTokenPrefix):]

	// Step 3: Confirm the reset.
	err = svc.ConfirmPasswordReset(ctx, token, "brand-new-password-12345")
	require.NoError(t, err)

	// Step 4: Token should be consumed.
	exists, err := svc.redis.Exists(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists)
}

func TestGenerateResetToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool, 100)
	for i := 0; i < 100; i++ {
		token, err := generateResetToken()
		require.NoError(t, err)
		assert.Len(t, token, resetTokenBytes*2, "hex-encoded token length")
		assert.False(t, tokens[token], "token collision at iteration %d", i)
		tokens[token] = true
	}
}

func TestRegister_ReturnsStub(t *testing.T) {
	svc := newTestService(t)
	user, err := svc.Register(context.Background(), "test@example.com", "password123456789", "Test")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test", user.Name)
	assert.NotEmpty(t, user.ID)
}

func TestGetMe_ReturnsStub(t *testing.T) {
	svc := newTestService(t)
	user, err := svc.GetMe(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", user.ID)
}
