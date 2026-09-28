package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
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

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockUserRepository struct {
	findByEmailFn             func(ctx context.Context, email string) (*domain.User, error)
	findByIDFn                func(ctx context.Context, id string) (*domain.User, error)
	createFn                  func(ctx context.Context, user *domain.User) (*domain.User, error)
	updateLastLogin           func(ctx context.Context, userID string, ts time.Time) error
	updatePasswordHashFn      func(ctx context.Context, userID, newHash string) error
	updateNameFn              func(ctx context.Context, userID, name string) error
	getPasswordHistoryFn      func(ctx context.Context, userID string, limit int) ([]domain.PasswordHistoryEntry, error)
	addPasswordHistoryFn      func(ctx context.Context, userID, hash string) error
	setEmailVerifyTokenFn     func(ctx context.Context, userID, token string, expiresAt time.Time) error
	consumeEmailVerifyTokenFn func(ctx context.Context, token string) (*domain.User, error)
	setPendingEmailChangeFn   func(ctx context.Context, userID, pendingEmail, changeToken string, changeExpiresAt time.Time, revertToken string, revertExpiresAt time.Time) error
	consumeEmailChangeTokenFn func(ctx context.Context, token string) (*domain.User, error)
	consumeEmailRevertTokenFn func(ctx context.Context, token string) (*domain.User, error)
}

func (m *mockUserRepository) Create(ctx context.Context, user *domain.User) (*domain.User, error) {
	if m.createFn != nil {
		return m.createFn(ctx, user)
	}
	return user, nil
}

func (m *mockUserRepository) FindByID(ctx context.Context, _ uuid.UUID, id string) (*domain.User, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, _ uuid.UUID, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, storage.ErrNotFound
}

func (m *mockUserRepository) UpdateLastLogin(ctx context.Context, _ uuid.UUID, userID string, ts time.Time) error {
	if m.updateLastLogin != nil {
		return m.updateLastLogin(ctx, userID, ts)
	}
	return nil
}

func (m *mockUserRepository) SetEmailVerifyToken(ctx context.Context, _ uuid.UUID, userID string, token string, expiresAt time.Time) error {
	if m.setEmailVerifyTokenFn != nil {
		return m.setEmailVerifyTokenFn(ctx, userID, token, expiresAt)
	}
	return nil
}

func (m *mockUserRepository) ConsumeEmailVerifyToken(ctx context.Context, _ uuid.UUID, token string) (*domain.User, error) {
	if m.consumeEmailVerifyTokenFn != nil {
		return m.consumeEmailVerifyTokenFn(ctx, token)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) UpdatePasswordHash(ctx context.Context, _ uuid.UUID, userID, newHash string) error {
	if m.updatePasswordHashFn != nil {
		return m.updatePasswordHashFn(ctx, userID, newHash)
	}
	return nil
}

func (m *mockUserRepository) UpdateName(ctx context.Context, _ uuid.UUID, userID, name string) error {
	if m.updateNameFn != nil {
		return m.updateNameFn(ctx, userID, name)
	}
	return nil
}

func (m *mockUserRepository) SetForcePasswordChange(_ context.Context, _ uuid.UUID, _ string, _ bool) error {
	return nil
}

func (m *mockUserRepository) GetPasswordHistory(ctx context.Context, _ uuid.UUID, userID string, limit int) ([]domain.PasswordHistoryEntry, error) {
	if m.getPasswordHistoryFn != nil {
		return m.getPasswordHistoryFn(ctx, userID, limit)
	}
	return nil, nil
}

func (m *mockUserRepository) AddPasswordHistory(ctx context.Context, _ uuid.UUID, userID, hash string) error {
	if m.addPasswordHistoryFn != nil {
		return m.addPasswordHistoryFn(ctx, userID, hash)
	}
	return nil
}

func (m *mockUserRepository) SetPendingEmailChange(ctx context.Context, _ uuid.UUID, userID, pendingEmail, changeToken string, changeExpiresAt time.Time, revertToken string, revertExpiresAt time.Time) error {
	if m.setPendingEmailChangeFn != nil {
		return m.setPendingEmailChangeFn(ctx, userID, pendingEmail, changeToken, changeExpiresAt, revertToken, revertExpiresAt)
	}
	return nil
}

func (m *mockUserRepository) ConsumeEmailChangeToken(ctx context.Context, _ uuid.UUID, token string) (*domain.User, error) {
	if m.consumeEmailChangeTokenFn != nil {
		return m.consumeEmailChangeTokenFn(ctx, token)
	}
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) ConsumeEmailRevertToken(ctx context.Context, _ uuid.UUID, token string) (*domain.User, error) {
	if m.consumeEmailRevertTokenFn != nil {
		return m.consumeEmailRevertTokenFn(ctx, token)
	}
	return nil, fmt.Errorf("not implemented")
}

type mockRefreshTokenRepository struct {
	storeFn          func(ctx context.Context, sig, userID string, exp time.Time) error
	revokeFn         func(ctx context.Context, sig string) error
	revokeAllForUser func(ctx context.Context, userID string) error
}

func (m *mockRefreshTokenRepository) Store(ctx context.Context, _ uuid.UUID, sig, userID string, exp time.Time) error {
	if m.storeFn != nil {
		return m.storeFn(ctx, sig, userID, exp)
	}
	return nil
}

func (m *mockRefreshTokenRepository) FindBySignature(_ context.Context, _ uuid.UUID, _ string) (*domain.RefreshTokenRecord, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockRefreshTokenRepository) Revoke(ctx context.Context, _ uuid.UUID, sig string) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, sig)
	}
	return nil
}

func (m *mockRefreshTokenRepository) RevokeAllForUser(ctx context.Context, _ uuid.UUID, userID string) error {
	if m.revokeAllForUser != nil {
		return m.revokeAllForUser(ctx, userID)
	}
	return nil
}

type mockTokenIssuer struct {
	issueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType) (*api.AuthResult, error)
	revokeFn         func(ctx context.Context, token string) error
}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType, _ ...string) (*api.AuthResult, error) {
	if m.issueTokenPairFn != nil {
		return m.issueTokenPairFn(ctx, subject, roles, scopes, ct)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test-access",
		RefreshToken: "qf_rt_test-key.test-refresh-sig",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

func (m *mockTokenIssuer) Revoke(ctx context.Context, token string) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, token)
	}
	return nil
}

type mockBreachChecker struct {
	isBreachedFn func(ctx context.Context, password string) (bool, error)
}

func (m *mockBreachChecker) IsBreached(ctx context.Context, password string) (bool, error) {
	if m.isBreachedFn != nil {
		return m.isBreachedFn(ctx, password)
	}
	return false, nil
}

type mockEmailSender struct {
	sendFn func(ctx context.Context, msg email.Message) error
	sent   []email.Message
}

func (m *mockEmailSender) Send(ctx context.Context, msg email.Message) error {
	m.sent = append(m.sent, msg)
	if m.sendFn != nil {
		return m.sendFn(ctx, msg)
	}
	return nil
}

type mockHasher struct {
	verifyFn       func(password, hash string) (bool, error)
	needsUpgradeFn func(hash string) bool
}

func (m *mockHasher) Hash(_ string) (string, error) {
	return "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g", nil
}

func (m *mockHasher) Verify(password, hash string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(password, hash)
	}
	return true, nil
}

func (m *mockHasher) NeedsUpgrade(hash string) bool {
	if m.needsUpgradeFn != nil {
		return m.needsUpgradeFn(hash)
	}
	return false
}

// ── Test helpers ─────────────────────────────────────────────────────────────

// newUnitService creates a Service with a nil Redis client for pure unit tests
// that don't exercise password-reset (Redis-dependent) code paths.
func newUnitService(t *testing.T, users *mockUserRepository, tokens *mockRefreshTokenRepository, issuer *mockTokenIssuer, hasher *mockHasher) *Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  audit.NopLogger{},
		Users:    users,
		Tokens:   tokens,
		Issuer:   issuer,
		Hasher:   hasher,
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})
}

// newUnitServiceWithEmail creates a Service with a nil Redis client and a
// caller-supplied user repository / email sender / verify URL base, for
// register and verify-email unit tests that don't touch Redis.
func newUnitServiceWithEmail(t *testing.T, users *mockUserRepository, sender email.EmailSender, verifyURLBase string) *Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewService(ServiceDeps{
		Redis:         nil,
		Logger:        logger,
		Auditor:       audit.NopLogger{},
		Users:         users,
		Tokens:        &mockRefreshTokenRepository{},
		Issuer:        &mockTokenIssuer{},
		Hasher:        &mockHasher{},
		Breaches:      &mockBreachChecker{},
		Email:         sender,
		VerifyURLBase: verifyURLBase,
	})
}

// newRedisClient creates a Redis client for integration tests (password reset).
// Tests are skipped when Redis is unavailable.
func newRedisClient(t *testing.T) *redis.Client {
	t.Helper()

	client := redis.NewClient(&redis.Options{
		Addr: "localhost:6379",
		DB:   15,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		t.Skipf("redis unavailable, skipping integration test: %v", err)
	}

	_, err := client.FlushDB(ctx).Result()
	require.NoError(t, err)

	t.Cleanup(func() {
		_, _ = client.FlushDB(context.Background()).Result()
		_ = client.Close()
	})

	return client
}

// newIntegrationService creates a Service with a real Redis client and a user
// repository that resolves any email to a found user, for tests exercising
// the Redis-backed reset/confirm flow that don't care about the lookup
// outcome itself.
func newIntegrationService(t *testing.T) *Service {
	t.Helper()
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr, PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g"}, nil
		},
	}
	return newIntegrationServiceWithDeps(t, users, &mockEmailSender{}, "")
}

// newIntegrationServiceWithDeps creates a Service with a real Redis client and
// caller-supplied user repository / email sender, for tests that assert on
// email delivery behavior.
func newIntegrationServiceWithDeps(t *testing.T, users *mockUserRepository, sender email.EmailSender, resetURLBase string) *Service {
	t.Helper()
	client := newRedisClient(t)
	logger, _ := zap.NewDevelopment()
	return NewService(ServiceDeps{
		Redis:        client,
		Logger:       logger,
		Auditor:      audit.NopLogger{},
		Users:        users,
		Tokens:       &mockRefreshTokenRepository{},
		Issuer:       &mockTokenIssuer{},
		Hasher:       &mockHasher{},
		Breaches:     &mockBreachChecker{},
		Email:        sender,
		ResetURLBase: resetURLBase,
	})
}

// newEmailChangeService creates a Service with a real Redis client (needed by
// RequestEmailChange's rate limiter) and caller-supplied user repository,
// email sender, and auditor. Email delivery is enabled with configured
// confirm/revert URL bases, matching a fully-configured production deployment.
func newEmailChangeService(t *testing.T, users *mockUserRepository, sender email.EmailSender, auditor audit.EventLogger) *Service {
	t.Helper()
	client := newRedisClient(t)
	logger, _ := zap.NewDevelopment()
	return NewService(ServiceDeps{
		Redis:                     client,
		Logger:                    logger,
		Auditor:                   auditor,
		Users:                     users,
		Tokens:                    &mockRefreshTokenRepository{},
		Issuer:                    &mockTokenIssuer{},
		Hasher:                    &mockHasher{},
		Breaches:                  &mockBreachChecker{},
		Email:                     sender,
		EmailEnabled:              true,
		EmailChangeConfirmURLBase: "https://app.example.com/email-change/confirm",
		EmailChangeRevertURLBase:  "https://app.example.com/email-change/revert",
	})
}

// ── Login Tests ──────────────────────────────────────────────────────────────

func TestLogin(t *testing.T) {
	activeUser := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Name:         "Alice",
		Roles:        []string{"user"},
	}

	lockedUser := &domain.User{
		ID:           "user-2",
		Email:        "locked@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Name:         "Locked User",
		Roles:        []string{"user"},
		Locked:       true,
	}

	now := time.Now()
	suspendedUser := &domain.User{
		ID:           "user-3",
		Email:        "suspended@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Name:         "Suspended User",
		Roles:        []string{"user"},
		DeletedAt:    &now,
	}

	tests := []struct {
		name      string
		email     string
		password  string
		users     *mockUserRepository
		hasher    *mockHasher
		issuer    *mockTokenIssuer
		wantErr   bool
		errTarget error
	}{
		{
			name:     "success",
			email:    "alice@example.com",
			password: "correct-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, email string) (*domain.User, error) {
					if email == "alice@example.com" {
						return activeUser, nil
					}
					return nil, storage.ErrNotFound
				},
			},
			hasher:  &mockHasher{verifyFn: func(_, _ string) (bool, error) { return true, nil }},
			wantErr: false,
		},
		{
			name:     "user not found returns unauthorized",
			email:    "nobody@example.com",
			password: "any-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
					return nil, fmt.Errorf("email nobody@example.com: %w", storage.ErrNotFound)
				},
			},
			hasher:    &mockHasher{},
			wantErr:   true,
			errTarget: api.ErrUnauthorized,
		},
		{
			name:     "wrong password returns unauthorized",
			email:    "alice@example.com",
			password: "wrong-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser, nil
				},
			},
			hasher:    &mockHasher{verifyFn: func(_, _ string) (bool, error) { return false, nil }},
			wantErr:   true,
			errTarget: api.ErrUnauthorized,
		},
		{
			name:     "locked account returns unauthorized",
			email:    "locked@example.com",
			password: "correct-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
					return lockedUser, nil
				},
			},
			hasher:    &mockHasher{},
			wantErr:   true,
			errTarget: api.ErrUnauthorized,
		},
		{
			name:     "suspended account returns unauthorized",
			email:    "suspended@example.com",
			password: "correct-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
					return suspendedUser, nil
				},
			},
			hasher:    &mockHasher{},
			wantErr:   true,
			errTarget: api.ErrUnauthorized,
		},
		{
			name:     "token issuance failure",
			email:    "alice@example.com",
			password: "correct-password",
			users: &mockUserRepository{
				findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser, nil
				},
			},
			hasher: &mockHasher{verifyFn: func(_, _ string) (bool, error) { return true, nil }},
			issuer: &mockTokenIssuer{
				issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType) (*api.AuthResult, error) {
					return nil, fmt.Errorf("key error")
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			issuer := tt.issuer
			if issuer == nil {
				issuer = &mockTokenIssuer{}
			}
			svc := newUnitService(t, tt.users, &mockRefreshTokenRepository{}, issuer, tt.hasher)
			ctx := context.Background()

			result, err := svc.Login(ctx, tt.email, tt.password)
			if tt.wantErr {
				require.Error(t, err)
				if tt.errTarget != nil {
					assert.ErrorIs(t, err, tt.errTarget)
				}
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, "qf_at_test-access", result.AccessToken)
				assert.Equal(t, "qf_rt_test-key.test-refresh-sig", result.RefreshToken)
				assert.Equal(t, "Bearer", result.TokenType)
				assert.Equal(t, 900, result.ExpiresIn)
			}
		})
	}
}

// ── MFA Mocks ───────────────────────────────────────────────────────────────

type mockMFAChecker struct {
	isMFAEnabledFn     func(ctx context.Context, userID string) (bool, error)
	generateMFATokenFn func(ctx context.Context, userID string) (string, error)
}

func (m *mockMFAChecker) IsMFAEnabled(ctx context.Context, userID string) (bool, error) {
	if m.isMFAEnabledFn != nil {
		return m.isMFAEnabledFn(ctx, userID)
	}
	return false, nil
}

func (m *mockMFAChecker) GenerateMFAToken(ctx context.Context, userID string) (string, error) {
	if m.generateMFATokenFn != nil {
		return m.generateMFATokenFn(ctx, userID)
	}
	return "mfa-token-123", nil
}

// spyAuditor records emitted audit events for assertions.
type spyAuditor struct {
	events []audit.Event
}

func (s *spyAuditor) LogEvent(_ context.Context, event audit.Event) {
	s.events = append(s.events, event)
}

func TestLogin_MFAChallenge(t *testing.T) {
	activeUser := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:        []string{"user"},
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return activeUser, nil
		},
	}

	mfaChecker := &mockMFAChecker{
		isMFAEnabledFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
		generateMFATokenFn: func(_ context.Context, _ string) (string, error) {
			return "mfa-challenge-token", nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	svc.SetMFAChecker(mfaChecker)

	result, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.MFARequired, "expected MFA challenge")
	assert.Equal(t, "mfa-challenge-token", result.MFAToken)
	assert.Equal(t, "user-1", result.UserID)
	assert.Empty(t, result.AccessToken, "should not issue access token when MFA required")
}

func TestLogin_MFANotEnabled_ReturnsTokens(t *testing.T) {
	activeUser := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:        []string{"user"},
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return activeUser, nil
		},
	}

	mfaChecker := &mockMFAChecker{
		isMFAEnabledFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	svc.SetMFAChecker(mfaChecker)

	result, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.False(t, result.MFARequired)
	assert.Equal(t, "qf_at_test-access", result.AccessToken)
}

// TestLogin_MFAStatusCheckError_FailsClosed is a regression test for GH-488:
// an error checking MFA status must reject the login (NIST SP 800-63-4 AAL2)
// instead of silently falling back to a password-only login. Previously this
// path "failed open" and issued tokens anyway.
func TestLogin_MFAStatusCheckError_FailsClosed(t *testing.T) {
	activeUser := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:        []string{"user"},
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return activeUser, nil
		},
	}

	mfaChecker := &mockMFAChecker{
		isMFAEnabledFn: func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("mfa store unavailable")
		},
	}

	var issued bool
	issuer := &mockTokenIssuer{
		issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType) (*api.AuthResult, error) {
			issued = true
			return &api.AuthResult{}, nil
		},
	}

	auditor := &spyAuditor{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  auditor,
		Users:    users,
		Tokens:   &mockRefreshTokenRepository{},
		Issuer:   issuer,
		Hasher:   &mockHasher{},
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})
	svc.SetMFAChecker(mfaChecker)

	result, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
	assert.Nil(t, result)
	assert.False(t, issued, "no tokens should be issued when the mfa status check fails")

	var sawEvent bool
	for _, e := range auditor.events {
		if e.Type == "mfa_status_check_failed" {
			sawEvent = true
			assert.Equal(t, "user-1", e.ActorID)
		}
	}
	assert.True(t, sawEvent, "expected mfa_status_check_failed audit event")
}

func TestLogin_UpdatesLastLogin(t *testing.T) {
	var lastLoginUpdated bool
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				Email:        "alice@example.com",
				PasswordHash: "hash",
				Roles:        []string{"user"},
			}, nil
		},
		updateLastLogin: func(_ context.Context, _ string, _ time.Time) error {
			lastLoginUpdated = true
			return nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	_, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	assert.True(t, lastLoginUpdated, "expected last_login_at to be updated")
}

func TestLogin_StoresRefreshTokenSignature(t *testing.T) {
	var stored bool
	var storedExpiry time.Time
	tokens := &mockRefreshTokenRepository{
		storeFn: func(_ context.Context, sig, userID string, exp time.Time) error {
			stored = true
			// Only the signature segment (after the dot) should be stored,
			// never the full "qf_rt_<key>.<sig>" token (GH-486).
			assert.Equal(t, "test-refresh-sig", sig)
			assert.Equal(t, "user-1", userID)
			storedExpiry = exp
			return nil
		},
	}
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				Email:        "alice@example.com",
				PasswordHash: "hash",
				Roles:        []string{"user"},
			}, nil
		},
	}

	svc := newUnitService(t, users, tokens, &mockTokenIssuer{}, &mockHasher{})
	_, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	assert.True(t, stored, "expected refresh token signature to be stored")
	// newUnitService doesn't configure RefreshTokenTTL, so the default fallback applies.
	assert.WithinDuration(t, time.Now().Add(defaultRefreshTokenTTL), storedExpiry, 5*time.Second)
}

func TestLogin_StoresRefreshTokenSignature_UsesConfiguredTTL(t *testing.T) {
	var storedExpiry time.Time
	tokens := &mockRefreshTokenRepository{
		storeFn: func(_ context.Context, _, _ string, exp time.Time) error {
			storedExpiry = exp
			return nil
		},
	}
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				Email:        "alice@example.com",
				PasswordHash: "hash",
				Roles:        []string{"user"},
			}, nil
		},
	}

	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Logger:          logger,
		Auditor:         audit.NopLogger{},
		Users:           users,
		Tokens:          tokens,
		Issuer:          &mockTokenIssuer{},
		Hasher:          &mockHasher{},
		Breaches:        &mockBreachChecker{},
		Email:           &mockEmailSender{},
		RefreshTokenTTL: 7 * 24 * time.Hour,
	})

	_, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	assert.WithinDuration(t, time.Now().Add(7*24*time.Hour), storedExpiry, 5*time.Second)
}

func TestLogin_MalformedRefreshTokenSkipsStore(t *testing.T) {
	var stored bool
	tokens := &mockRefreshTokenRepository{
		storeFn: func(_ context.Context, _, _ string, _ time.Time) error {
			stored = true
			return nil
		},
	}
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				Email:        "alice@example.com",
				PasswordHash: "hash",
				Roles:        []string{"user"},
			}, nil
		},
	}
	issuer := &mockTokenIssuer{
		issueTokenPairFn: func(_ context.Context, _ string, _, _ []string, _ domain.ClientType) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_test-access",
				RefreshToken: "qf_rt_no-dot-here",
				TokenType:    "Bearer",
				ExpiresIn:    900,
			}, nil
		},
	}

	svc := newUnitService(t, users, tokens, issuer, &mockHasher{})
	_, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err, "login must succeed even when the signature parse fails (best-effort store)")
	assert.False(t, stored, "malformed refresh token must not be stored")
}

// ── Logout Tests ─────────────────────────────────────────────────────────────

func TestLogout(t *testing.T) {
	tests := []struct {
		name    string
		issuer  *mockTokenIssuer
		wantErr bool
	}{
		{
			name:    "success",
			issuer:  &mockTokenIssuer{},
			wantErr: false,
		},
		{
			name: "revoke failure propagates",
			issuer: &mockTokenIssuer{
				revokeFn: func(_ context.Context, _ string) error {
					return fmt.Errorf("redis down")
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newUnitService(t, &mockUserRepository{}, &mockRefreshTokenRepository{}, tt.issuer, &mockHasher{})
			err := svc.Logout(context.Background(), "user-1", "qf_at_some-token", "")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLogout_RevokesAccessToken(t *testing.T) {
	var revokedToken string
	issuer := &mockTokenIssuer{
		revokeFn: func(_ context.Context, token string) error {
			revokedToken = token
			return nil
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, &mockRefreshTokenRepository{}, issuer, &mockHasher{})
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token", "")
	require.NoError(t, err)
	assert.Equal(t, "qf_at_my-access-token", revokedToken)
}

// TestLogout_RevokesRefreshTokenSignature is a regression test for GH-486:
// Logout's doc comment claimed the refresh token's DB row was revoked, but
// the implementation never touched it, so a rotated-away token stayed
// introspectable as active until its row's original TTL expired. When the
// caller supplies the refresh token, its signature must be revoked too.
func TestLogout_RevokesRefreshTokenSignature(t *testing.T) {
	var revokedSig string
	tokens := &mockRefreshTokenRepository{
		revokeFn: func(_ context.Context, sig string) error {
			revokedSig = sig
			return nil
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, tokens, &mockTokenIssuer{}, &mockHasher{})
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token", "qf_rt_key123.sig456")
	require.NoError(t, err)
	assert.Equal(t, "sig456", revokedSig)
}

// TestLogout_NoRefreshTokenSkipsRevoke confirms logout stays functional
// (access-token-only) when the caller doesn't supply a refresh token — the
// common case for /auth/logout callers that don't send a body.
func TestLogout_NoRefreshTokenSkipsRevoke(t *testing.T) {
	var revokeCalled bool
	tokens := &mockRefreshTokenRepository{
		revokeFn: func(_ context.Context, _ string) error {
			revokeCalled = true
			return nil
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, tokens, &mockTokenIssuer{}, &mockHasher{})
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token", "")
	require.NoError(t, err)
	assert.False(t, revokeCalled)
}

// TestLogout_MalformedRefreshTokenSkipsRevoke confirms a malformed refresh
// token doesn't fail logout or reach the DB revoke call.
func TestLogout_MalformedRefreshTokenSkipsRevoke(t *testing.T) {
	var revokeCalled bool
	tokens := &mockRefreshTokenRepository{
		revokeFn: func(_ context.Context, _ string) error {
			revokeCalled = true
			return nil
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, tokens, &mockTokenIssuer{}, &mockHasher{})
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token", "qf_rt_no-dot-here")
	require.NoError(t, err)
	assert.False(t, revokeCalled)
}

// TestLogout_RefreshTokenRevokeFailureDoesNotFailLogout confirms the DB
// revoke is best-effort: a failure there must not fail the overall logout,
// since the access-token Redis blocklist entry is the primary signal.
func TestLogout_RefreshTokenRevokeFailureDoesNotFailLogout(t *testing.T) {
	tokens := &mockRefreshTokenRepository{
		revokeFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("db down")
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, tokens, &mockTokenIssuer{}, &mockHasher{})
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token", "qf_rt_key123.sig456")
	require.NoError(t, err)
}

// ── LogoutAll Tests ──────────────────────────────────────────────────────────

func TestLogoutAll(t *testing.T) {
	tests := []struct {
		name    string
		tokens  *mockRefreshTokenRepository
		wantErr bool
	}{
		{
			name:    "success",
			tokens:  &mockRefreshTokenRepository{},
			wantErr: false,
		},
		{
			name: "revoke all failure propagates",
			tokens: &mockRefreshTokenRepository{
				revokeAllForUser: func(_ context.Context, _ string) error {
					return fmt.Errorf("db down")
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newUnitService(t, &mockUserRepository{}, tt.tokens, &mockTokenIssuer{}, &mockHasher{})
			err := svc.LogoutAll(context.Background(), "user-1")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestLogoutAll_RevokesAllForUser(t *testing.T) {
	var revokedForUser string
	tokens := &mockRefreshTokenRepository{
		revokeAllForUser: func(_ context.Context, userID string) error {
			revokedForUser = userID
			return nil
		},
	}

	svc := newUnitService(t, &mockUserRepository{}, tokens, &mockTokenIssuer{}, &mockHasher{})
	err := svc.LogoutAll(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", revokedForUser)
}

// ── Password Reset Tests (integration, require Redis) ────────────────────────

func TestResetPassword_StoresTokenInRedis(t *testing.T) {
	svc := newIntegrationService(t)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "user@example.com")
	require.NoError(t, err)

	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1, "expected exactly one reset token in Redis")

	email, err := svc.redis.Get(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", email)

	ttl, err := svc.redis.TTL(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.True(t, ttl > 0 && ttl <= resetTokenTTL, "expected TTL in (0, %v], got %v", resetTokenTTL, ttl)
}

func TestConfirmPasswordReset_ValidToken(t *testing.T) {
	svc := newIntegrationService(t)
	ctx := context.Background()

	token := "test-reset-token-abc123"
	key := resetTokenPrefix + token
	err := svc.redis.Set(ctx, key, "user@example.com", resetTokenTTL).Err()
	require.NoError(t, err)

	err = svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	exists, err := svc.redis.Exists(ctx, key).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists, "token should be deleted after confirmation")
}

func TestConfirmPasswordReset_InvalidToken(t *testing.T) {
	svc := newIntegrationService(t)
	ctx := context.Background()

	err := svc.ConfirmPasswordReset(ctx, "nonexistent-token", "new-secure-password-12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestConfirmPasswordReset_TokenUsedOnce(t *testing.T) {
	svc := newIntegrationService(t)
	ctx := context.Background()

	token := "one-time-token"
	key := resetTokenPrefix + token
	err := svc.redis.Set(ctx, key, "user@example.com", resetTokenTTL).Err()
	require.NoError(t, err)

	err = svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	err = svc.ConfirmPasswordReset(ctx, token, "another-password-67890")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestResetPassword_FullFlow(t *testing.T) {
	svc := newIntegrationService(t)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "alice@example.com")
	require.NoError(t, err)

	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)

	token := keys[0][len(resetTokenPrefix):]

	err = svc.ConfirmPasswordReset(ctx, token, "brand-new-password-12345")
	require.NoError(t, err)

	exists, err := svc.redis.Exists(ctx, keys[0]).Result()
	require.NoError(t, err)
	assert.Equal(t, int64(0), exists)
}

// ── Password Reset Email Tests ──────────────────────────────────────────────

func TestResetPassword_KnownUser_SendsResetLink(t *testing.T) {
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr}, nil
		},
	}
	sender := &mockEmailSender{}
	svc := newIntegrationServiceWithDeps(t, users, sender, "https://app.example.com/reset")
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "alice@example.com")
	require.NoError(t, err)

	require.Len(t, sender.sent, 1, "expected exactly one email to be sent")
	msg := sender.sent[0]
	assert.Equal(t, "alice@example.com", msg.To)

	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	token := keys[0][len(resetTokenPrefix):]

	assert.Contains(t, msg.Body, "https://app.example.com/reset?token="+token)
}

func TestResetPassword_UnknownEmail_NoSendNoRedisWrite(t *testing.T) {
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	sender := &mockEmailSender{}
	svc := newIntegrationServiceWithDeps(t, users, sender, "https://app.example.com/reset")
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "nobody@example.com")
	require.NoError(t, err, "unknown email must still return nil (202, anti-enumeration)")

	assert.Empty(t, sender.sent, "expected zero emails sent for an unknown address")

	keys, err := svc.redis.Keys(ctx, resetTokenPrefix+"*").Result()
	require.NoError(t, err)
	assert.Empty(t, keys, "expected zero reset tokens stored for an unknown address")
}

func TestResetPassword_EmailSendFailure_StillReturnsNil(t *testing.T) {
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr}, nil
		},
	}
	sender := &mockEmailSender{
		sendFn: func(_ context.Context, _ email.Message) error {
			return fmt.Errorf("email service unreachable")
		},
	}
	svc := newIntegrationServiceWithDeps(t, users, sender, "https://app.example.com/reset")

	err := svc.ResetPassword(context.Background(), "alice@example.com")
	require.NoError(t, err, "delivery failure must not become an enumeration oracle")
	assert.Len(t, sender.sent, 1, "send should still have been attempted")
}

func TestResetPassword_ConsoleSenderPath(t *testing.T) {
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, addr string) (*domain.User, error) {
			return &domain.User{ID: "user-1", Email: addr}, nil
		},
	}
	logger, _ := zap.NewDevelopment()
	svc := newIntegrationServiceWithDeps(t, users, email.NewConsoleSender(logger), "https://app.example.com/reset")

	err := svc.ResetPassword(context.Background(), "alice@example.com")
	require.NoError(t, err, "ConsoleSender path (EMAIL_ENABLED=false) must not error")
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
	svc := newUnitService(t, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	user, err := svc.Register(context.Background(), "test@example.com", "password123456789", "Test")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test", user.Name)
	assert.NotEmpty(t, user.ID)
}

func TestGetMe_ReturnsUserProfile(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, id string) (*domain.User, error) {
			assert.Equal(t, "user-42", id)
			return &domain.User{
				ID:    "user-42",
				Email: "aleks@example.com",
				Name:  "Aleks Petrov",
			}, nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	user, err := svc.GetMe(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", user.ID)
	assert.Equal(t, "aleks@example.com", user.Email)
	assert.Equal(t, "Aleks Petrov", user.Name)
}

func TestGetMe_DifferentUsersGetDifferentProfiles(t *testing.T) {
	profiles := map[string]*domain.User{
		"user-1": {ID: "user-1", Email: "one@example.com", Name: "User One"},
		"user-2": {ID: "user-2", Email: "two@example.com", Name: "User Two"},
	}
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, id string) (*domain.User, error) {
			return profiles[id], nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	user1, err := svc.GetMe(context.Background(), "user-1")
	require.NoError(t, err)
	assert.Equal(t, "one@example.com", user1.Email)
	assert.Equal(t, "User One", user1.Name)

	user2, err := svc.GetMe(context.Background(), "user-2")
	require.NoError(t, err)
	assert.Equal(t, "two@example.com", user2.Email)
	assert.Equal(t, "User Two", user2.Name)
}

func TestGetMe_UserNotFound(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	user, err := svc.GetMe(context.Background(), "user-missing")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
	assert.Nil(t, user)
}

// ── UpdateProfile Tests ──────────────────────────────────────────────────────

func TestUpdateProfile_Success(t *testing.T) {
	var (
		updatedUserID, updatedName string
		updateCalls                int
	)
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, id string) (*domain.User, error) {
			assert.Equal(t, "user-42", id)
			return &domain.User{
				ID:    "user-42",
				Email: "aleks@example.com",
				Name:  "Old Name",
			}, nil
		},
		updateNameFn: func(_ context.Context, userID, name string) error {
			updateCalls++
			updatedUserID = userID
			updatedName = name
			return nil
		},
	}
	auditor := &spyAuditor{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  auditor,
		Users:    users,
		Tokens:   &mockRefreshTokenRepository{},
		Issuer:   &mockTokenIssuer{},
		Hasher:   &mockHasher{},
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})

	info, err := svc.UpdateProfile(context.Background(), "user-42", "New Name")
	require.NoError(t, err)
	assert.Equal(t, "user-42", info.ID)
	assert.Equal(t, "aleks@example.com", info.Email)
	assert.Equal(t, "New Name", info.Name)

	assert.Equal(t, 1, updateCalls, "UpdateName should be called exactly once")
	assert.Equal(t, "user-42", updatedUserID)
	assert.Equal(t, "New Name", updatedName)

	var profileEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventProfileUpdated {
			profileEvents = append(profileEvents, e)
		}
	}
	require.Len(t, profileEvents, 1, "expected exactly one profile_updated audit event")
	assert.Equal(t, "user-42", profileEvents[0].ActorID)
	assert.Equal(t, "user-42", profileEvents[0].TargetID)
}

func TestUpdateProfile_UserNotFound(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	info, err := svc.UpdateProfile(context.Background(), "user-missing", "New Name")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
	assert.Nil(t, info)
}

func TestUpdateProfile_RepositoryError(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, id string) (*domain.User, error) {
			return &domain.User{ID: id, Email: "aleks@example.com", Name: "Old Name"}, nil
		},
		updateNameFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("db unavailable")
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	info, err := svc.UpdateProfile(context.Background(), "user-42", "New Name")
	require.Error(t, err)
	assert.Nil(t, info)
}

// ── Register Tests ──────────────────────────────────────────────────────────

func TestRegister_PolicyValidation(t *testing.T) {
	svc := newUnitService(t, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	_, err := svc.Register(context.Background(), "test@example.com", "short", "Test")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
}

func TestRegister_CreatesUser(t *testing.T) {
	var createdUser *domain.User
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			createdUser = u
			return u, nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	info, err := svc.Register(context.Background(), "test@example.com", "valid-password-12345", "Test User")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", info.Email)
	assert.Equal(t, "Test User", info.Name)
	assert.NotEmpty(t, info.ID)
	require.NotNil(t, createdUser)
	assert.NotEmpty(t, createdUser.PasswordHash)
	assert.NotNil(t, createdUser.PasswordChangedAt)
}

func TestRegister_IssuesEmailVerificationTokenAndSendsLink(t *testing.T) {
	var (
		tokenUserID string
		tokenValue  string
		expiresAt   time.Time
	)
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			u.ID = "user-1"
			return u, nil
		},
		setEmailVerifyTokenFn: func(_ context.Context, userID, token string, expiry time.Time) error {
			tokenUserID = userID
			tokenValue = token
			expiresAt = expiry
			return nil
		},
	}
	sender := &mockEmailSender{}
	svc := newUnitServiceWithEmail(t, users, sender, "https://app.example.com/verify-email")

	before := time.Now().UTC()
	info, err := svc.Register(context.Background(), "test@example.com", "valid-password-12345", "Test User")
	require.NoError(t, err)

	assert.Equal(t, "user-1", tokenUserID)
	assert.Len(t, tokenValue, resetTokenBytes*2, "hex-encoded 32-byte token")
	assert.WithinDuration(t, before.Add(verifyTokenTTL), expiresAt, 2*time.Second)

	require.Len(t, sender.sent, 1, "expected exactly one verification email to be sent")
	msg := sender.sent[0]
	assert.Equal(t, info.Email, msg.To)
	assert.Contains(t, msg.Body, "https://app.example.com/verify-email?token="+tokenValue)
}

func TestRegister_EmailSendFailure_RegistrationStillSucceeds(t *testing.T) {
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			u.ID = "user-1"
			return u, nil
		},
	}
	sender := &mockEmailSender{
		sendFn: func(_ context.Context, _ email.Message) error {
			return fmt.Errorf("email service unreachable")
		},
	}
	svc := newUnitServiceWithEmail(t, users, sender, "https://app.example.com/verify-email")

	info, err := svc.Register(context.Background(), "test@example.com", "valid-password-12345", "Test User")
	require.NoError(t, err, "a verification email delivery failure must not fail registration")
	assert.Equal(t, "test@example.com", info.Email)
	assert.Len(t, sender.sent, 1, "send should still have been attempted")
}

func TestRegister_ConsoleSenderPath_RegistrationUnchanged(t *testing.T) {
	users := &mockUserRepository{
		createFn: func(_ context.Context, u *domain.User) (*domain.User, error) {
			u.ID = "user-1"
			return u, nil
		},
	}
	logger, _ := zap.NewDevelopment()
	svc := newUnitServiceWithEmail(t, users, email.NewConsoleSender(logger), "")

	info, err := svc.Register(context.Background(), "test@example.com", "valid-password-12345", "Test User")
	require.NoError(t, err, "ConsoleSender path (EMAIL_ENABLED=false) must not error")
	assert.Equal(t, "test@example.com", info.Email)
}

// ── VerifyEmail Tests ────────────────────────────────────────────────────────

func TestVerifyEmail(t *testing.T) {
	verifiedUser := &domain.User{ID: "user-1", Email: "alice@example.com", EmailVerified: true}

	tests := []struct {
		name    string
		token   string
		users   *mockUserRepository
		wantErr bool
	}{
		{
			name:  "happy path",
			token: "valid-token",
			users: &mockUserRepository{
				consumeEmailVerifyTokenFn: func(_ context.Context, token string) (*domain.User, error) {
					assert.Equal(t, "valid-token", token)
					return verifiedUser, nil
				},
			},
			wantErr: false,
		},
		{
			name:  "already verified is idempotent",
			token: "already-used-token",
			users: &mockUserRepository{
				consumeEmailVerifyTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
					return verifiedUser, nil
				},
			},
			wantErr: false,
		},
		{
			name:  "expired token",
			token: "expired-token",
			users: &mockUserRepository{
				consumeEmailVerifyTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
					return nil, fmt.Errorf("email verify token: %w", storage.ErrTokenExpired)
				},
			},
			wantErr: true,
		},
		{
			name:  "invalid token",
			token: "bogus-token",
			users: &mockUserRepository{
				consumeEmailVerifyTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
					return nil, fmt.Errorf("email verify token: %w", storage.ErrNotFound)
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newUnitService(t, tt.users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

			err := svc.VerifyEmail(context.Background(), tt.token)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

// ── ChangePassword Tests ────────────────────────────────────────────────────

func TestChangePassword_Success(t *testing.T) {
	existingHash := "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g"
	var updatedHash string
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				PasswordHash: existingHash,
			}, nil
		},
		updatePasswordHashFn: func(_ context.Context, _ string, newHash string) error {
			updatedHash = newHash
			return nil
		},
	}
	hasher := &mockHasher{
		verifyFn: func(pwd, hash string) (bool, error) {
			if pwd == "old-password-12345" && hash == existingHash {
				return true, nil
			}
			return false, nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, hasher)
	err := svc.ChangePassword(context.Background(), "user-1", "old-password-12345", "new-password-67890")
	require.NoError(t, err)
	assert.NotEmpty(t, updatedHash)
}

func TestChangePassword_WrongOldPassword(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
			}, nil
		},
	}
	hasher := &mockHasher{
		verifyFn: func(_, _ string) (bool, error) { return false, nil },
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, hasher)
	err := svc.ChangePassword(context.Background(), "user-1", "wrong-old-password", "new-password-67890")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestChangePassword_NewPasswordTooShort(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{
				ID:           "user-1",
				PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
			}, nil
		},
	}
	hasher := &mockHasher{
		verifyFn: func(_, _ string) (bool, error) { return true, nil },
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, hasher)
	err := svc.ChangePassword(context.Background(), "user-1", "old-password-12345", "short")
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrPasswordTooShort)
}

// ── Login Hash Upgrade Tests ────────────────────────────────────────────────

func TestLogin_HashUpgrade(t *testing.T) {
	var upgradedHash string
	bcryptUser := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$2a$10$dGVzdGJjcnlwdGhhc2g",
		Roles:        []string{"user"},
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return bcryptUser, nil
		},
		updatePasswordHashFn: func(_ context.Context, _ string, newHash string) error {
			upgradedHash = newHash
			return nil
		},
	}

	hasher := &mockHasher{
		verifyFn:       func(_, _ string) (bool, error) { return true, nil },
		needsUpgradeFn: func(hash string) bool { return hash == "$2a$10$dGVzdGJjcnlwdGhhc2g" },
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, hasher)
	result, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, upgradedHash, "hash should be upgraded on login")
}

func TestLogin_ForcePasswordChange(t *testing.T) {
	user := &domain.User{
		ID:                  "user-1",
		Email:               "alice@example.com",
		PasswordHash:        "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:               []string{"user"},
		ForcePasswordChange: true,
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return user, nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	result, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.ForcePasswordChange)
	assert.Empty(t, result.AccessToken, "should not issue tokens when password change required")
}

func TestLogin_PasswordExpired(t *testing.T) {
	expired := time.Now().Add(-200 * 24 * time.Hour)
	user := &domain.User{
		ID:                "user-1",
		Email:             "alice@example.com",
		PasswordHash:      "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:             []string{"user"},
		PasswordChangedAt: &expired,
	}

	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return user, nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	// Set a policy with 90-day max age.
	svc.SetPasswordPolicy(password.NewPolicyValidator(domain.PasswordPolicy{
		MinLength:  15,
		MaxAgeDays: 90,
	}, &mockHasher{}))

	result, err := svc.Login(context.Background(), "alice@example.com", "password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.ForcePasswordChange)
}

// ── RequestEmailChange Tests (integration, require Redis) ───────────────────

func emailChangeTestUser() *domain.User {
	return &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
	}
}

func TestRequestEmailChange_Success(t *testing.T) {
	var (
		gotUserID, gotPendingEmail, gotChangeToken, gotRevertToken string
		gotChangeExpiresAt, gotRevertExpiresAt                     time.Time
	)
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
		setPendingEmailChangeFn: func(_ context.Context, userID, pendingEmail, changeToken string, changeExpiresAt time.Time, revertToken string, revertExpiresAt time.Time) error {
			gotUserID = userID
			gotPendingEmail = pendingEmail
			gotChangeToken = changeToken
			gotChangeExpiresAt = changeExpiresAt
			gotRevertToken = revertToken
			gotRevertExpiresAt = revertExpiresAt
			return nil
		},
	}
	sender := &mockEmailSender{}
	auditor := &spyAuditor{}
	svc := newEmailChangeService(t, users, sender, auditor)

	before := time.Now().UTC()
	result, err := svc.RequestEmailChange(context.Background(), "user-1", "new@example.com", "correct-password")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "pending", result.Status)
	assert.Equal(t, "new@example.com", result.PendingEmail)

	assert.Equal(t, "user-1", gotUserID)
	assert.Equal(t, "new@example.com", gotPendingEmail)
	assert.Len(t, gotChangeToken, resetTokenBytes*2, "hex-encoded 32-byte token")
	assert.Len(t, gotRevertToken, resetTokenBytes*2, "hex-encoded 32-byte token")
	assert.NotEqual(t, gotChangeToken, gotRevertToken)
	assert.WithinDuration(t, before.Add(emailChangeTokenTTL), gotChangeExpiresAt, 2*time.Second)
	assert.WithinDuration(t, before.Add(emailRevertTokenTTL), gotRevertExpiresAt, 2*time.Second)

	require.Len(t, sender.sent, 2, "expected a confirmation email to the new address and a notice to the old one")
	confirmMsg := sender.sent[0]
	assert.Equal(t, "new@example.com", confirmMsg.To)
	assert.Equal(t, "Confirm your new email", confirmMsg.Subject)
	assert.Contains(t, confirmMsg.Body, "https://app.example.com/email-change/confirm?token="+gotChangeToken)

	noticeMsg := sender.sent[1]
	assert.Equal(t, "alice@example.com", noticeMsg.To)
	assert.Equal(t, "Your email is being changed", noticeMsg.Subject)
	assert.Contains(t, noticeMsg.Body, "https://app.example.com/email-change/revert?token="+gotRevertToken)
	assert.Contains(t, noticeMsg.Body, "example.com", "should name the new address's domain")
	assert.NotContains(t, noticeMsg.Body, "new@example.com", "must not leak the full new address to the old inbox")

	var reqEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventEmailChangeRequested {
			reqEvents = append(reqEvents, e)
		}
	}
	require.Len(t, reqEvents, 1)
	assert.Equal(t, "user-1", reqEvents[0].ActorID)
	assert.Equal(t, "user-1", reqEvents[0].TargetID)
	assert.Equal(t, "new@example.com", reqEvents[0].Metadata["new_email"])
}

func TestRequestEmailChange_WrongPassword(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
	}
	hasher := &mockHasher{
		verifyFn: func(pwd, _ string) (bool, error) { return pwd == "correct-password", nil },
	}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:                     newRedisClient(t),
		Logger:                    logger,
		Auditor:                   &spyAuditor{},
		Users:                     users,
		Tokens:                    &mockRefreshTokenRepository{},
		Issuer:                    &mockTokenIssuer{},
		Hasher:                    hasher,
		Breaches:                  &mockBreachChecker{},
		Email:                     &mockEmailSender{},
		EmailEnabled:              true,
		EmailChangeConfirmURLBase: "https://app.example.com/email-change/confirm",
		EmailChangeRevertURLBase:  "https://app.example.com/email-change/revert",
	})

	result, err := svc.RequestEmailChange(context.Background(), "user-1", "new@example.com", "wrong-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInvalidPassword)
	assert.Nil(t, result)
}

func TestRequestEmailChange_SameEmail(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
	}
	svc := newEmailChangeService(t, users, &mockEmailSender{}, &spyAuditor{})

	result, err := svc.RequestEmailChange(context.Background(), "user-1", "ALICE@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
	assert.Nil(t, result)
}

func TestRequestEmailChange_EmailTaken(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return &domain.User{ID: "someone-else"}, nil
		},
	}
	svc := newEmailChangeService(t, users, &mockEmailSender{}, &spyAuditor{})

	result, err := svc.RequestEmailChange(context.Background(), "user-1", "taken@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
	assert.Nil(t, result)
}

func TestRequestEmailChange_RateLimited(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	client := newRedisClient(t)
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:                     client,
		Logger:                    logger,
		Auditor:                   &spyAuditor{},
		Users:                     users,
		Tokens:                    &mockRefreshTokenRepository{},
		Issuer:                    &mockTokenIssuer{},
		Hasher:                    &mockHasher{},
		Breaches:                  &mockBreachChecker{},
		Email:                     &mockEmailSender{},
		EmailEnabled:              true,
		EmailChangeConfirmURLBase: "https://app.example.com/email-change/confirm",
		EmailChangeRevertURLBase:  "https://app.example.com/email-change/revert",
	})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := svc.RequestEmailChange(ctx, "user-1", "new@example.com", "correct-password")
		require.NoError(t, err, "request %d should be within the rate limit", i+1)
	}

	_, err := svc.RequestEmailChange(ctx, "user-1", "new@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrRateLimited)

	// INCR and EXPIRE must have landed together on every call (see
	// checkEmailChangeRateLimit) so the key can never exist without a TTL.
	key := fmt.Sprintf("%s%s:%s", emailChangeRatePrefix, domain.DefaultTenantID, "user-1")
	ttl, err := client.TTL(ctx, key).Result()
	require.NoError(t, err)
	assert.Greater(t, ttl, time.Duration(0), "rate limit key must have a TTL")
	assert.LessOrEqual(t, ttl, emailChangeRateWindow, "TTL should be at most one hour after the first call")
}

// TestRequestEmailChange_RateLimitCountsEveryRequest asserts that failed
// (wrong-password) attempts count against the rate limit exactly like
// successful ones, since checkEmailChangeRateLimit runs before the password
// check. Otherwise an attacker could brute-force the password indefinitely
// by never supplying a correct one.
func TestRequestEmailChange_RateLimitCountsEveryRequest(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	hasher := &mockHasher{
		verifyFn: func(pwd, _ string) (bool, error) { return pwd == "correct-password", nil },
	}
	sender := &mockEmailSender{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:                     newRedisClient(t),
		Logger:                    logger,
		Auditor:                   &spyAuditor{},
		Users:                     users,
		Tokens:                    &mockRefreshTokenRepository{},
		Issuer:                    &mockTokenIssuer{},
		Hasher:                    hasher,
		Breaches:                  &mockBreachChecker{},
		Email:                     sender,
		EmailEnabled:              true,
		EmailChangeConfirmURLBase: "https://app.example.com/email-change/confirm",
		EmailChangeRevertURLBase:  "https://app.example.com/email-change/revert",
	})
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		_, err := svc.RequestEmailChange(ctx, "user-1", "new@example.com", "wrong-password")
		require.Error(t, err, "request %d should fail the password check", i+1)
		assert.ErrorIs(t, err, api.ErrInvalidPassword)
	}

	// The fourth call supplies the correct password, but the three prior
	// wrong-password calls should already have exhausted the limit.
	_, err := svc.RequestEmailChange(ctx, "user-1", "new@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrRateLimited)
	assert.Empty(t, sender.sent, "no email should have been sent")
}

func TestRequestEmailChange_Unconfigured(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:        nil,
		Logger:       logger,
		Auditor:      audit.NopLogger{},
		Users:        &mockUserRepository{},
		Tokens:       &mockRefreshTokenRepository{},
		Issuer:       &mockTokenIssuer{},
		Hasher:       &mockHasher{},
		Breaches:     &mockBreachChecker{},
		Email:        &mockEmailSender{},
		EmailEnabled: true,
		// EmailChangeConfirmURLBase / EmailChangeRevertURLBase left unset.
	})

	result, err := svc.RequestEmailChange(context.Background(), "user-1", "new@example.com", "correct-password")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrEmailChangeUnconfigured)
	assert.Nil(t, result)
}

func TestRequestEmailChange_EmailSendFailure_StillSucceeds(t *testing.T) {
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
	}
	sender := &mockEmailSender{
		sendFn: func(_ context.Context, _ email.Message) error {
			return fmt.Errorf("email service unreachable")
		},
	}
	auditor := &spyAuditor{}
	svc := newEmailChangeService(t, users, sender, auditor)

	result, err := svc.RequestEmailChange(context.Background(), "user-1", "new@example.com", "correct-password")
	require.NoError(t, err, "email delivery failure must not fail the request")
	require.NotNil(t, result)
	assert.Equal(t, "pending", result.Status)
	assert.Len(t, sender.sent, 2, "both sends should still have been attempted")

	var failedEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventEmailChangeEmailFailed {
			failedEvents = append(failedEvents, e)
		}
	}
	require.Len(t, failedEvents, 2, "expected a failure audit event for each of the two emails")
	stages := map[string]bool{}
	for _, e := range failedEvents {
		stages[e.Metadata["stage"]] = true
	}
	assert.True(t, stages["confirm"])
	assert.True(t, stages["revert"])
}

func TestRequestEmailChange_SecondRequestReplacesTokens(t *testing.T) {
	var seenChangeTokens, seenRevertTokens []string
	users := &mockUserRepository{
		findByIDFn: func(_ context.Context, _ string) (*domain.User, error) {
			return emailChangeTestUser(), nil
		},
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, storage.ErrNotFound
		},
		setPendingEmailChangeFn: func(_ context.Context, _, _, changeToken string, _ time.Time, revertToken string, _ time.Time) error {
			seenChangeTokens = append(seenChangeTokens, changeToken)
			seenRevertTokens = append(seenRevertTokens, revertToken)
			return nil
		},
	}
	svc := newEmailChangeService(t, users, &mockEmailSender{}, &spyAuditor{})
	ctx := context.Background()

	_, err := svc.RequestEmailChange(ctx, "user-1", "new@example.com", "correct-password")
	require.NoError(t, err)
	_, err = svc.RequestEmailChange(ctx, "user-1", "new@example.com", "correct-password")
	require.NoError(t, err)

	require.Len(t, seenChangeTokens, 2)
	require.Len(t, seenRevertTokens, 2)
	assert.NotEqual(t, seenChangeTokens[0], seenChangeTokens[1], "second request should mint a new change token")
	assert.NotEqual(t, seenRevertTokens[0], seenRevertTokens[1], "second request should mint a new revert token")
}

// ── ConfirmEmailChange Tests ─────────────────────────────────────────────────

func TestConfirmEmailChange_Success(t *testing.T) {
	var revokedForUser string
	users := &mockUserRepository{
		consumeEmailChangeTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			assert.Equal(t, "valid-change-token", token)
			return &domain.User{ID: "user-1", Email: "new@example.com"}, nil
		},
	}
	tokens := &mockRefreshTokenRepository{
		revokeAllForUser: func(_ context.Context, userID string) error {
			revokedForUser = userID
			return nil
		},
	}
	auditor := &spyAuditor{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  auditor,
		Users:    users,
		Tokens:   tokens,
		Issuer:   &mockTokenIssuer{},
		Hasher:   &mockHasher{},
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})

	err := svc.ConfirmEmailChange(context.Background(), "valid-change-token")
	require.NoError(t, err)
	assert.Equal(t, "user-1", revokedForUser, "sessions must be revoked after an email change")

	var changedEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventEmailChanged {
			changedEvents = append(changedEvents, e)
		}
	}
	require.Len(t, changedEvents, 1)
	assert.Equal(t, "user-1", changedEvents[0].ActorID)
	assert.Equal(t, "user-1", changedEvents[0].TargetID)
	assert.Equal(t, "new@example.com", changedEvents[0].Metadata["email"])
}

func TestConfirmEmailChange_UnknownToken(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailChangeTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("email change token: %w", storage.ErrNotFound)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.ConfirmEmailChange(context.Background(), "bogus-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// TestConfirmEmailChange_ConsumedToken mimics the real repository's
// one-time-use semantics: the token works on the first confirm and looks
// unknown on any subsequent one, since ConsumeEmailChangeToken deletes it on
// success. The second call must report api.ErrNotFound just like an
// unknown token (mapped to 400 by the handler, never 404).
func TestConfirmEmailChange_ConsumedToken(t *testing.T) {
	consumed := false
	users := &mockUserRepository{
		consumeEmailChangeTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			assert.Equal(t, "once-only-token", token)
			if consumed {
				return nil, fmt.Errorf("email change token: %w", storage.ErrNotFound)
			}
			consumed = true
			return &domain.User{ID: "user-1", Email: "new@example.com"}, nil
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.ConfirmEmailChange(context.Background(), "once-only-token")
	require.NoError(t, err, "first confirm should succeed")

	err = svc.ConfirmEmailChange(context.Background(), "once-only-token")
	require.Error(t, err, "second confirm with the same token must fail")
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestConfirmEmailChange_ExpiredToken(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailChangeTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("email change token: %w", storage.ErrTokenExpired)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.ConfirmEmailChange(context.Background(), "expired-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrGone)
}

func TestConfirmEmailChange_EmailTakenMeanwhile(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailChangeTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("email taken: %w", storage.ErrDuplicateEmail)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.ConfirmEmailChange(context.Background(), "some-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// ── RevertEmailChange Tests ──────────────────────────────────────────────────

func TestRevertEmailChange_AfterOnlyRequested(t *testing.T) {
	var revokedForUser string
	users := &mockUserRepository{
		consumeEmailRevertTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			assert.Equal(t, "valid-revert-token", token)
			// previous_email was never set, so the current email is the
			// original address and is left untouched by the repo layer.
			return &domain.User{ID: "user-1", Email: "alice@example.com"}, nil
		},
	}
	tokens := &mockRefreshTokenRepository{
		revokeAllForUser: func(_ context.Context, userID string) error {
			revokedForUser = userID
			return nil
		},
	}
	auditor := &spyAuditor{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  auditor,
		Users:    users,
		Tokens:   tokens,
		Issuer:   &mockTokenIssuer{},
		Hasher:   &mockHasher{},
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})

	err := svc.RevertEmailChange(context.Background(), "valid-revert-token")
	require.NoError(t, err)
	assert.Equal(t, "user-1", revokedForUser)

	var revertedEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventEmailChangeReverted {
			revertedEvents = append(revertedEvents, e)
		}
	}
	require.Len(t, revertedEvents, 1)
	assert.Equal(t, "user-1", revertedEvents[0].ActorID)
	assert.Equal(t, "alice@example.com", revertedEvents[0].Metadata["email"])
}

func TestRevertEmailChange_AfterConfirmedChange(t *testing.T) {
	var revokedForUser string
	users := &mockUserRepository{
		consumeEmailRevertTokenFn: func(_ context.Context, token string) (*domain.User, error) {
			assert.Equal(t, "valid-revert-token", token)
			// previous_email was set by a prior ConsumeEmailChangeToken call;
			// the repo layer has already restored it onto Email.
			return &domain.User{ID: "user-1", Email: "alice@example.com"}, nil
		},
	}
	tokens := &mockRefreshTokenRepository{
		revokeAllForUser: func(_ context.Context, userID string) error {
			revokedForUser = userID
			return nil
		},
	}
	auditor := &spyAuditor{}
	logger, _ := zap.NewDevelopment()
	svc := NewService(ServiceDeps{
		Redis:    nil,
		Logger:   logger,
		Auditor:  auditor,
		Users:    users,
		Tokens:   tokens,
		Issuer:   &mockTokenIssuer{},
		Hasher:   &mockHasher{},
		Breaches: &mockBreachChecker{},
		Email:    &mockEmailSender{},
	})

	err := svc.RevertEmailChange(context.Background(), "valid-revert-token")
	require.NoError(t, err)
	assert.Equal(t, "user-1", revokedForUser, "sessions must be revoked after a revert too")

	var revertedEvents []audit.Event
	for _, e := range auditor.events {
		if e.Type == audit.EventEmailChangeReverted {
			revertedEvents = append(revertedEvents, e)
		}
	}
	require.Len(t, revertedEvents, 1)
}

func TestRevertEmailChange_UnknownToken(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailRevertTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("email revert token: %w", storage.ErrNotFound)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.RevertEmailChange(context.Background(), "bogus-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestRevertEmailChange_ExpiredToken(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailRevertTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("email revert token: %w", storage.ErrTokenExpired)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.RevertEmailChange(context.Background(), "expired-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrGone)
}

func TestRevertEmailChange_EmailTakenMeanwhile(t *testing.T) {
	users := &mockUserRepository{
		consumeEmailRevertTokenFn: func(_ context.Context, _ string) (*domain.User, error) {
			return nil, fmt.Errorf("previous email taken: %w", storage.ErrDuplicateEmail)
		},
	}
	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})

	err := svc.RevertEmailChange(context.Background(), "some-token")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}
