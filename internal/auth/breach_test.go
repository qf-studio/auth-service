package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

const breachTestNewPassword = "new-password-67890-xyz"

// newBreachTestService wires a Service with miniredis, a fake breach checker,
// a spy auditor and an observed logger.
func newBreachTestService(t *testing.T, checker *mockBreachChecker) (*Service, *spyAuditor, *observer.ObservedLogs, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	core, logs := observer.New(zapcore.WarnLevel)
	spy := &spyAuditor{}
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr, PasswordHash: "old-hash"}, nil
		},
		findByIDFn: func(_ context.Context, id string) (*domain.User, error) {
			return &domain.User{ID: id, Email: "alice@example.com", PasswordHash: "old-hash"}, nil
		},
	}
	svc := NewService(ServiceDeps{
		Redis:    client,
		Logger:   zap.New(core),
		Auditor:  spy,
		Users:    users,
		Tokens:   &mockRefreshTokenRepository{},
		Issuer:   &mockTokenIssuer{},
		Hasher:   &mockHasher{verifyFn: func(_, _ string) (bool, error) { return true, nil }},
		Breaches: checker,
		Email:    &mockEmailSender{},
	})
	return svc, spy, logs, mr
}

func auditTypes(spy *spyAuditor) []string {
	types := make([]string, 0, len(spy.events))
	for _, e := range spy.events {
		types = append(types, e.Type)
	}
	return types
}

func TestBreachedPassword_AllFlows(t *testing.T) {
	flows := []struct {
		name    string
		flowTag string
		run     func(t *testing.T, svc *Service, mr *miniredis.Miniredis) error
	}{
		{"register", "register", func(_ *testing.T, svc *Service, _ *miniredis.Miniredis) error {
			_, err := svc.Register(context.Background(), "alice@example.com", breachTestNewPassword, "Alice")
			return err
		}},
		{"confirm_password_reset", "password_reset", func(t *testing.T, svc *Service, mr *miniredis.Miniredis) error {
			require.NoError(t, mr.Set(resetTokenPrefix+"tok", "alice@example.com"))
			return svc.ConfirmPasswordReset(context.Background(), "tok", breachTestNewPassword)
		}},
		{"change_password", "password_change", func(_ *testing.T, svc *Service, _ *miniredis.Miniredis) error {
			return svc.ChangePassword(context.Background(), "user-1", "old-password-12345", breachTestNewPassword)
		}},
	}

	for _, f := range flows {
		t.Run(f.name+"/breached_rejected", func(t *testing.T) {
			var got string
			svc, spy, _, mr := newBreachTestService(t, &mockBreachChecker{isBreachedFn: func(_ context.Context, pwd string) (bool, error) {
				got = pwd
				return true, nil
			}})

			err := f.run(t, svc, mr)
			require.ErrorIs(t, err, domain.ErrPasswordBreached)
			assert.Equal(t, "password appears in a known data breach; choose another", err.Error())
			assert.Equal(t, breachTestNewPassword, got)
			assert.Contains(t, auditTypes(spy), audit.EventPasswordBreached)
			assert.NotContains(t, auditTypes(spy), audit.EventRegister)
			assert.NotContains(t, auditTypes(spy), audit.EventPasswordChange)
			assert.NotContains(t, auditTypes(spy), audit.EventPasswordResetConfm)
		})

		t.Run(f.name+"/not_breached_succeeds", func(t *testing.T) {
			svc, spy, logs, mr := newBreachTestService(t, &mockBreachChecker{})

			require.NoError(t, f.run(t, svc, mr))
			assert.NotContains(t, auditTypes(spy), audit.EventPasswordBreached)
			assert.NotContains(t, auditTypes(spy), audit.EventBreachCheckFailed)
			assert.Zero(t, logs.Len())
		})

		t.Run(f.name+"/service_error_fails_open", func(t *testing.T) {
			svc, spy, logs, mr := newBreachTestService(t, &mockBreachChecker{isBreachedFn: func(context.Context, string) (bool, error) {
				return false, errors.New("hibp: request failed: context deadline exceeded")
			}})

			require.NoError(t, f.run(t, svc, mr))
			assert.Contains(t, auditTypes(spy), audit.EventBreachCheckFailed)
			warns := logs.FilterLevelExact(zapcore.WarnLevel).All()
			require.Len(t, warns, 1)
			assert.Equal(t, f.flowTag, warns[0].ContextMap()["flow"])
		})
	}
}

func TestBreachedPassword_PolicyRunsBeforeBreachCheck(t *testing.T) {
	called := false
	svc, _, _, _ := newBreachTestService(t, &mockBreachChecker{isBreachedFn: func(context.Context, string) (bool, error) {
		called = true
		return true, nil
	}})

	_, err := svc.Register(context.Background(), "alice@example.com", "short", "Alice")
	require.ErrorIs(t, err, domain.ErrPasswordTooShort)
	assert.False(t, called, "too-short passwords must not be sent to the breach service")
}
