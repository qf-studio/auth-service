package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/storage"
)

func TestRedisMFAStore_FailedAttemptsExceeded(t *testing.T) {
	tests := []struct {
		name     string
		failures int
		want     bool
	}{
		{name: "no failures", failures: 0, want: false},
		{name: "below limit", failures: 2, want: false},
		{name: "at limit", failures: 3, want: true},
		{name: "over limit", failures: 4, want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, client := newTestRedis(t)
			store := storage.NewRedisMFAStore(client, storage.WithMaxMFAAttempts(3))
			ctx := context.Background()

			for i := 0; i < tt.failures; i++ {
				_, _ = store.RecordFailedAttempt(ctx, "user-1")
			}

			got, err := store.FailedAttemptsExceeded(ctx, "user-1")
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestRedisMFAStore_MarkTOTPUsed(t *testing.T) {
	mr, client := newTestRedis(t)
	store := storage.NewRedisMFAStore(client)
	ctx := context.Background()

	fresh, err := store.MarkTOTPUsed(ctx, "user-1", 1000, 90*time.Second)
	require.NoError(t, err)
	assert.True(t, fresh, "first use of a step is accepted")

	fresh, err = store.MarkTOTPUsed(ctx, "user-1", 1000, 90*time.Second)
	require.NoError(t, err)
	assert.False(t, fresh, "second use of the same step is rejected")

	fresh, err = store.MarkTOTPUsed(ctx, "user-2", 1000, 90*time.Second)
	require.NoError(t, err)
	assert.True(t, fresh, "steps are tracked per user")

	fresh, err = store.MarkTOTPUsed(ctx, "user-1", 1001, 90*time.Second)
	require.NoError(t, err)
	assert.True(t, fresh, "the next step is a different code")

	assert.True(t, mr.Exists("mfa:used:user-1:1000"))
	assert.Equal(t, 90*time.Second, mr.TTL("mfa:used:user-1:1000"))

	mr.FastForward(91 * time.Second)
	assert.False(t, mr.Exists("mfa:used:user-1:1000"), "used-code record expires")
}
