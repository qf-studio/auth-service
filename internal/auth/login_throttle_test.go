package auth

import (
	"context"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	throttleMaxFailures = 10
	throttleLockout     = 15 * time.Minute
	throttleGoodPwd     = "correct-password"
)

// throttleHarness wires a Service to the real AccountRateLimiter on
// miniredis, with a hasher that accepts only throttleGoodPwd and counts how
// often a password was actually checked.
type throttleHarness struct {
	svc              *Service
	mr               *miniredis.Miniredis
	verifyCalls      int
	callsBeforeFinal int
}

func newThrottleHarness(t *testing.T) *throttleHarness {
	t.Helper()
	h := &throttleHarness{}
	h.mr = miniredis.RunT(t)
	// No retries and a short dial timeout keep the Redis-down case fast.
	client := redis.NewClient(&redis.Options{Addr: h.mr.Addr(), MaxRetries: -1, DialTimeout: 200 * time.Millisecond})
	t.Cleanup(func() { _ = client.Close() })

	limiter := middleware.NewAccountRateLimiter(client, config.RateLimitConfig{
		ProgressiveDelayAfter: 5,
		MaxFailedAttempts:     throttleMaxFailures,
		LockoutDuration:       throttleLockout,
	})

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, email string) (*domain.User, error) {
			if email == "alice@example.com" || email == "Alice@Example.com" {
				return &domain.User{ID: "user-1", Email: "alice@example.com", PasswordHash: "hash", Roles: []string{"user"}}, nil
			}
			return nil, storage.ErrNotFound
		},
	}
	hasher := &mockHasher{verifyFn: func(pwd, _ string) (bool, error) {
		h.verifyCalls++
		return pwd == throttleGoodPwd, nil
	}}

	h.svc = NewService(ServiceDeps{
		Redis:         client,
		Logger:        zap.NewNop(),
		Auditor:       audit.NopLogger{},
		Users:         users,
		Tokens:        &mockRefreshTokenRepository{},
		Issuer:        &mockTokenIssuer{},
		Hasher:        hasher,
		Breaches:      &mockBreachChecker{},
		Email:         &mockEmailSender{},
		LoginThrottle: limiter,
	})
	return h
}

// fail makes n logins with a wrong password.
func (h *throttleHarness) fail(ctx context.Context, t *testing.T, email string, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		_, err := h.svc.Login(ctx, email, "wrong-password")
		require.ErrorIs(t, err, api.ErrUnauthorized, "failure %d", i+1)
	}
}

// finalLogin makes the scenario's last login, with the correct password.
func (h *throttleHarness) finalLogin(ctx context.Context, email string) error {
	h.callsBeforeFinal = h.verifyCalls
	_, err := h.svc.Login(ctx, email, throttleGoodPwd)
	return err
}

func TestLogin_AccountThrottle(t *testing.T) {
	ctx := context.Background()
	const alice = "alice@example.com"

	tests := []struct {
		name string
		// run performs the scenario, ending with finalLogin.
		run     func(t *testing.T, h *throttleHarness) error
		wantErr error
	}{
		{
			name: "10 failures then correct password is throttled",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, alice, throttleMaxFailures)
				return h.finalLogin(ctx, alice)
			},
			wantErr: api.ErrRateLimited,
		},
		{
			name: "9 failures then correct password succeeds",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, alice, throttleMaxFailures-1)
				return h.finalLogin(ctx, alice)
			},
		},
		{
			name: "lockout expires after the window",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, alice, throttleMaxFailures)
				h.mr.FastForward(throttleLockout + time.Second)
				return h.finalLogin(ctx, alice)
			},
		},
		{
			name: "success resets the counter",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, alice, throttleMaxFailures-1)
				_, err := h.svc.Login(ctx, alice, throttleGoodPwd)
				require.NoError(t, err)
				h.fail(ctx, t, alice, throttleMaxFailures-1)
				return h.finalLogin(ctx, alice)
			},
		},
		{
			name: "email case variants share one counter",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, "Alice@Example.com", throttleMaxFailures)
				return h.finalLogin(ctx, alice)
			},
			wantErr: api.ErrRateLimited,
		},
		{
			name: "unknown email is throttled the same way",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, "nobody@example.com", throttleMaxFailures)
				return h.finalLogin(ctx, "nobody@example.com")
			},
			wantErr: api.ErrRateLimited,
		},
		{
			name: "other tenant is not affected",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(domain.WithTenantID(ctx, uuid.New()), t, alice, throttleMaxFailures)
				return h.finalLogin(ctx, alice)
			},
		},
		{
			name: "redis unavailable fails open",
			run: func(t *testing.T, h *throttleHarness) error {
				h.fail(ctx, t, alice, throttleMaxFailures)
				h.mr.Close()
				return h.finalLogin(ctx, alice)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newThrottleHarness(t)
			err := tt.run(t, h)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Equal(t, h.callsBeforeFinal, h.verifyCalls, "throttled attempt must not verify the password")
				return
			}
			require.NoError(t, err)
		})
	}
}
