package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/pquerna/otp/totp"
	redisv9 "github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// newRedisBackedService wires the real RedisMFAStore (on miniredis) so the
// failed-attempt counter and the used-code cache behave as in production.
func newRedisBackedService(t *testing.T, repo *mockMFARepository) (*Service, *storage.RedisMFAStore) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redisv9.NewClient(&redisv9.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })
	store := storage.NewRedisMFAStore(rc)

	svc, err := NewService(DefaultConfig(), repo, store, &mockTokenIssuer{}, &mockUserLookup{}, zap.NewNop(), audit.NopLogger{})
	require.NoError(t, err)
	return svc, store
}

func confirmedSecretRepo(secret string, confirmed bool) *mockMFARepository {
	return &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{Secret: secret, Confirmed: confirmed}, nil
		},
	}
}

// waitForFreshTOTPStep blocks until the current 30 s TOTP step has at least
// a few seconds left, so a test making several calls with one code doesn't
// straddle a step boundary.
func waitForFreshTOTPStep() {
	for time.Now().Unix()%30 > 25 {
		time.Sleep(100 * time.Millisecond)
	}
}

func TestVerifyTOTP_AttemptLimitAndReuse(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)

	tests := []struct {
		name string
		// priorFailures is the number of failed attempts recorded before the
		// correct code is submitted.
		priorFailures int
		// submissions is how many times the same correct code is submitted.
		submissions int
		// wantErrs is the expected error for each submission (nil = success).
		wantErrs []error
	}{
		{name: "correct code under limit succeeds", priorFailures: 4, submissions: 1, wantErrs: []error{nil}},
		{name: "correct code at limit rejected", priorFailures: 5, submissions: 1, wantErrs: []error{api.ErrForbidden}},
		{name: "same code twice rejects the second", submissions: 2, wantErrs: []error{nil, api.ErrUnauthorized}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			waitForFreshTOTPStep()
			svc, store := newRedisBackedService(t, confirmedSecretRepo(key.Secret(), true))
			ctx := context.Background()

			for i := 0; i < tt.priorFailures; i++ {
				_, _ = store.RecordFailedAttempt(ctx, "user-1")
			}

			code, err := totp.GenerateCode(key.Secret(), time.Now())
			require.NoError(t, err)

			for i := 0; i < tt.submissions; i++ {
				err := svc.VerifyTOTP(ctx, "user-1", code)
				if tt.wantErrs[i] == nil {
					require.NoError(t, err, "submission %d", i+1)
				} else {
					require.Error(t, err, "submission %d", i+1)
					assert.ErrorIs(t, err, tt.wantErrs[i], "submission %d", i+1)
				}
			}
		})
	}
}

func TestVerifyTOTP_AtLimitDoesNotConsumeCode(t *testing.T) {
	// A correct code rejected by the attempt limit must not be recorded as
	// used: the check runs before validation.
	waitForFreshTOTPStep()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)
	svc, store := newRedisBackedService(t, confirmedSecretRepo(key.Secret(), true))
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, _ = store.RecordFailedAttempt(ctx, "user-1")
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	err = svc.VerifyTOTP(ctx, "user-1", code)
	require.ErrorIs(t, err, api.ErrForbidden)

	require.NoError(t, store.ClearFailedAttempts(ctx, "user-1"))
	require.NoError(t, svc.VerifyTOTP(ctx, "user-1", code))
}

func TestConfirmEnrollment_CodeIsSingleUse(t *testing.T) {
	// The code used to confirm enrollment can't be replayed for verification
	// within the same step.
	waitForFreshTOTPStep()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)

	confirmed := false
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{Secret: key.Secret(), Confirmed: confirmed}, nil
		},
		confirmSecretFn: func(_ context.Context, _ string) error {
			confirmed = true
			return nil
		},
	}
	svc, _ := newRedisBackedService(t, repo)
	ctx := context.Background()

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = svc.ConfirmEnrollment(ctx, "user-1", code)
	require.NoError(t, err)

	err = svc.VerifyTOTP(ctx, "user-1", code)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestConfirmEnrollment_AtLimitRejected(t *testing.T) {
	waitForFreshTOTPStep()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)
	svc, store := newRedisBackedService(t, confirmedSecretRepo(key.Secret(), false))
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, _ = store.RecordFailedAttempt(ctx, "user-1")
	}
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	_, err = svc.ConfirmEnrollment(ctx, "user-1", code)
	require.ErrorIs(t, err, api.ErrForbidden)
}

func TestVerifyBackupCode_AtLimitRejectedWithoutConsuming(t *testing.T) {
	var consumed bool
	repo := &mockMFARepository{
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			consumed = true
			return nil
		},
	}
	svc, store := newRedisBackedService(t, repo)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		_, _ = store.RecordFailedAttempt(ctx, "user-1")
	}

	err := svc.VerifyBackupCode(ctx, "user-1", "abcd-1234-efgh-5678")
	require.ErrorIs(t, err, api.ErrForbidden)
	assert.False(t, consumed, "backup code must not be consumed once the limit is reached")
}

func TestCheckTOTP_StoreErrorsFailClosed(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)
	storeErr := errors.New("redis down")

	tests := []struct {
		name   string
		tokens *mockMFATokenStore
	}{
		{
			name: "attempt counter unreadable",
			tokens: &mockMFATokenStore{
				exceededFn: func(_ context.Context, _ string) (bool, error) { return false, storeErr },
			},
		},
		{
			name: "used-code record fails",
			tokens: &mockMFATokenStore{
				markUsedFn: func(_ context.Context, _ string, _ uint64, _ time.Duration) (bool, error) { return false, storeErr },
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(confirmedSecretRepo(key.Secret(), true), tt.tokens, &mockTokenIssuer{})
			code, err := totp.GenerateCode(key.Secret(), time.Now())
			require.NoError(t, err)

			err = svc.VerifyTOTP(context.Background(), "user-1", code)
			require.Error(t, err)
			assert.ErrorIs(t, err, api.ErrInternalError)
		})
	}
}

func TestCheckTOTP_UsedCodeKeyedOnTimeStep(t *testing.T) {
	waitForFreshTOTPStep()
	key, err := totp.Generate(totp.GenerateOpts{Issuer: "Test", AccountName: "alice@test.com"})
	require.NoError(t, err)

	var gotStep uint64
	var gotTTL time.Duration
	tokens := &mockMFATokenStore{
		markUsedFn: func(_ context.Context, _ string, step uint64, ttl time.Duration) (bool, error) {
			gotStep, gotTTL = step, ttl
			return true, nil
		},
	}
	svc := newTestService(confirmedSecretRepo(key.Secret(), true), tokens, &mockTokenIssuer{})

	now := time.Now()
	code, err := totp.GenerateCode(key.Secret(), now)
	require.NoError(t, err)
	require.NoError(t, svc.VerifyTOTP(context.Background(), "user-1", code))

	assert.Equal(t, uint64(now.Unix())/30, gotStep) //nolint:gosec // Unix time is positive
	assert.Equal(t, 90*time.Second, gotTTL)
}
