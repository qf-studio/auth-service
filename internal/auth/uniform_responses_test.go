package auth

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/email"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const testStoredHash = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g"

// hasherMatching returns a hasher whose Verify succeeds only for want, and
// counts the calls it receives.
func hasherMatching(want string, calls *[]string) *mockHasher {
	return &mockHasher{verifyFn: func(pwd, hash string) (bool, error) {
		*calls = append(*calls, hash)
		return pwd == want, nil
	}}
}

func TestLogin_AccountStateHiddenUntilPasswordVerified(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name     string
		user     *domain.User
		password string
		wantErr  error
		notErr   error
	}{
		{
			name:     "locked + wrong password is generic",
			user:     &domain.User{ID: "u1", PasswordHash: testStoredHash, Locked: true},
			password: "wrong-password-123456",
			wantErr:  domain.ErrInvalidCredentials,
			notErr:   domain.ErrAccountLocked,
		},
		{
			name:     "suspended + wrong password is generic",
			user:     &domain.User{ID: "u2", PasswordHash: testStoredHash, DeletedAt: &now},
			password: "wrong-password-123456",
			wantErr:  domain.ErrInvalidCredentials,
			notErr:   domain.ErrAccountSuspended,
		},
		{
			name:     "locked + correct password is revealed",
			user:     &domain.User{ID: "u1", PasswordHash: testStoredHash, Locked: true},
			password: "correct-password-123",
			wantErr:  domain.ErrAccountLocked,
		},
		{
			name:     "suspended + correct password is revealed",
			user:     &domain.User{ID: "u2", PasswordHash: testStoredHash, DeletedAt: &now},
			password: "correct-password-123",
			wantErr:  domain.ErrAccountSuspended,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var calls []string
			users := &mockUserRepository{
				findByEmailFn: func(context.Context, string) (*domain.User, error) { return tt.user, nil },
			}
			svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{},
				hasherMatching("correct-password-123", &calls))

			_, err := svc.Login(context.Background(), "alice@example.com", tt.password)
			require.ErrorIs(t, err, tt.wantErr)
			require.ErrorIs(t, err, api.ErrUnauthorized)
			if tt.notErr != nil {
				assert.NotErrorIs(t, err, tt.notErr)
			}
			assert.Equal(t, []string{testStoredHash}, calls, "password is verified before account state is considered")
		})
	}
}

func TestLogin_UnknownEmailRunsDummyVerifyOnce(t *testing.T) {
	var calls []string
	users := &mockUserRepository{
		findByEmailFn: func(context.Context, string) (*domain.User, error) { return nil, storage.ErrNotFound },
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{},
		hasherMatching("correct-password-123", &calls))

	_, err := svc.Login(context.Background(), "nobody@example.com", "whatever-password-1")
	require.ErrorIs(t, err, domain.ErrInvalidCredentials)
	require.ErrorIs(t, err, api.ErrUnauthorized)
	assert.Equal(t, []string{dummyPasswordHash}, calls, "unknown email must cost exactly one hash verification")
}

// The dummy hash must be a well-formed hash for the production hasher, or the
// unknown-email path would fail fast instead of doing Argon2id work.
func TestDummyPasswordHash_IsValidForProductionHasher(t *testing.T) {
	ok, err := password.New(nil).Verify("some-password-123456", dummyPasswordHash)
	require.NoError(t, err)
	assert.False(t, ok)
}

type auditRecorder struct {
	mu     sync.Mutex
	events []audit.Event
}

func (r *auditRecorder) LogEvent(_ context.Context, e audit.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func newRegisterService(t *testing.T, users *mockUserRepository, sender email.EmailSender, emailEnabled bool, rec audit.EventLogger) *Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewService(ServiceDeps{
		Logger:        logger,
		Auditor:       rec,
		Users:         users,
		Tokens:        &mockRefreshTokenRepository{},
		Issuer:        &mockTokenIssuer{},
		Hasher:        &mockHasher{},
		Breaches:      &mockBreachChecker{},
		Email:         sender,
		EmailEnabled:  emailEnabled,
		VerifyURLBase: "https://app.example.com/verify",
	})
}

func TestRegister_DuplicateEmail_LooksLikeSuccess(t *testing.T) {
	const pwd = "valid-password-12345"
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			if u.Email == "taken@example.com" {
				return nil, storage.ErrDuplicateEmail
			}
			return u, nil
		},
	}
	sender := &mockEmailSender{}
	rec := &auditRecorder{}
	svc := newRegisterService(t, users, sender, true, rec)
	ctx := context.Background()

	fresh, err := svc.Register(ctx, "new@example.com", pwd, "New")
	require.NoError(t, err)
	svc.waitBackground()
	sentAfterFresh := len(sender.sent)

	dup, err := svc.Register(ctx, "Taken@example.com", pwd, "Mallory")
	require.NoError(t, err, "a duplicate registration must not be distinguishable from a new one")
	svc.waitBackground()

	assert.NotEmpty(t, dup.ID)
	assert.Contains(t, dup.ID, "usr_", "same ID shape as a real registration")
	assert.Len(t, dup.ID, len(fresh.ID))
	assert.Equal(t, "taken@example.com", dup.Email)
	assert.Equal(t, "Mallory", dup.Name)

	require.Len(t, sender.sent, sentAfterFresh+1, "the existing owner is emailed")
	notice := sender.sent[len(sender.sent)-1]
	assert.Equal(t, "taken@example.com", notice.To)
	assert.NotContains(t, notice.Body, "token=", "the notice carries no credential")

	require.NotEmpty(t, rec.events)
	assert.Equal(t, audit.EventRegisterDuplicate, rec.events[len(rec.events)-1].Type)
}

func TestRegister_DuplicateEmail_EmailDisabled_NoSend(t *testing.T) {
	users := &mockUserRepository{
		createFn: func(context.Context, *domain.User) (*domain.User, error) { return nil, storage.ErrDuplicateEmail },
	}
	sender := &mockEmailSender{}
	svc := newRegisterService(t, users, sender, false, audit.NopLogger{})

	info, err := svc.Register(context.Background(), "taken@example.com", "valid-password-12345", "X")
	require.NoError(t, err)
	svc.waitBackground()
	assert.NotEmpty(t, info.ID)
	assert.Empty(t, sender.sent)
}

func TestRegister_OtherCreateErrorsStillFail(t *testing.T) {
	users := &mockUserRepository{
		createFn: func(context.Context, *domain.User) (*domain.User, error) { return nil, assert.AnError },
	}
	svc := newRegisterService(t, users, &mockEmailSender{}, true, audit.NopLogger{})

	_, err := svc.Register(context.Background(), "a@example.com", "valid-password-12345", "X")
	require.ErrorIs(t, err, assert.AnError)
}

func TestResetPassword_ReturnsBeforeEmailIsSent(t *testing.T) {
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr}, nil
		},
	}
	release := make(chan struct{})
	started := make(chan struct{})
	sender := &mockEmailSender{sendFn: func(context.Context, email.Message) error {
		close(started)
		<-release
		return nil
	}}
	svc := newIntegrationServiceWithDeps(t, users, sender, "https://app.example.com/reset")

	done := make(chan error, 1)
	go func() { done <- svc.ResetPassword(context.Background(), "alice@example.com") }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("ResetPassword blocked on email delivery")
	}
	<-started
	close(release)
	svc.waitBackground()
}

func TestSendEmailAsync_SurvivesRequestCancellation(t *testing.T) {
	sender := &mockEmailSender{sendFn: func(ctx context.Context, _ email.Message) error { return ctx.Err() }}
	svc := newRegisterService(t, &mockUserRepository{}, sender, true, audit.NopLogger{})

	ctx, cancel := context.WithCancel(context.Background())
	failed := false
	svc.sendEmailAsync(ctx, email.Message{To: "a@example.com"}, func() { failed = true })
	cancel()
	svc.waitBackground()

	require.Len(t, sender.sent, 1)
	assert.False(t, failed, "request cancellation must not abort a detached send")
}
