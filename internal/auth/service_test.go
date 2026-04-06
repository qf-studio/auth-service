package auth

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockUserRepository struct {
	findByEmailFn   func(ctx context.Context, email string) (*domain.User, error)
	updateLastLogin func(ctx context.Context, userID string, ts time.Time) error
}

func (m *mockUserRepository) Create(_ context.Context, _ *domain.User) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) FindByID(_ context.Context, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) FindByEmail(ctx context.Context, email string) (*domain.User, error) {
	if m.findByEmailFn != nil {
		return m.findByEmailFn(ctx, email)
	}
	return nil, storage.ErrNotFound
}

func (m *mockUserRepository) UpdateLastLogin(ctx context.Context, userID string, ts time.Time) error {
	if m.updateLastLogin != nil {
		return m.updateLastLogin(ctx, userID, ts)
	}
	return nil
}

func (m *mockUserRepository) SetEmailVerifyToken(_ context.Context, _ string, _ string, _ time.Time) error {
	return fmt.Errorf("not implemented")
}

func (m *mockUserRepository) ConsumeEmailVerifyToken(_ context.Context, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepository) SetForcePasswordChange(_ context.Context, _ string, _ bool) error {
	return nil
}

func (m *mockUserRepository) ListActiveUserIDs(_ context.Context, _, _ int) ([]string, error) {
	return nil, nil
}

type mockRefreshTokenRepository struct {
	storeFn          func(ctx context.Context, sig, userID string, exp time.Time) error
	revokeAllForUser func(ctx context.Context, userID string) error
}

func (m *mockRefreshTokenRepository) Store(ctx context.Context, sig, userID string, exp time.Time) error {
	if m.storeFn != nil {
		return m.storeFn(ctx, sig, userID, exp)
	}
	return nil
}

func (m *mockRefreshTokenRepository) FindBySignature(_ context.Context, _ string) (*domain.RefreshTokenRecord, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockRefreshTokenRepository) Revoke(_ context.Context, _ string) error {
	return nil
}

func (m *mockRefreshTokenRepository) RevokeAllForUser(ctx context.Context, userID string) error {
	if m.revokeAllForUser != nil {
		return m.revokeAllForUser(ctx, userID)
	}
	return nil
}

type mockTokenIssuer struct {
	issueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType) (*api.AuthResult, error)
	revokeFn         func(ctx context.Context, token string) error
}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType) (*api.AuthResult, error) {
	if m.issueTokenPairFn != nil {
		return m.issueTokenPairFn(ctx, subject, roles, scopes, ct)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test-access",
		RefreshToken: "qf_rt_test-refresh",
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

type mockHasher struct {
	verifyFn func(password, hash string) (bool, error)
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

// ── Test helpers ─────────────────────────────────────────────────────────────

// newUnitService creates a Service with a nil Redis client for pure unit tests
// that don't exercise password-reset (Redis-dependent) code paths.
func newUnitService(t *testing.T, users *mockUserRepository, tokens *mockRefreshTokenRepository, issuer *mockTokenIssuer, hasher *mockHasher) *Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewService(nil, logger, audit.NopLogger{}, users, tokens, issuer, hasher, &mockBreachChecker{})
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

// newIntegrationService creates a Service with a real Redis client.
func newIntegrationService(t *testing.T) *Service {
	t.Helper()
	client := newRedisClient(t)
	logger, _ := zap.NewDevelopment()
	return NewService(client, logger, audit.NopLogger{}, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{}, &mockBreachChecker{})
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
				assert.Equal(t, "qf_rt_test-refresh", result.RefreshToken)
				assert.Equal(t, "Bearer", result.TokenType)
				assert.Equal(t, 900, result.ExpiresIn)
			}
		})
	}
}

// ── MFA Mocks ───────────────────────────────────────────────────────────────

type mockMFAChecker struct {
	isMFAEnabledFn       func(ctx context.Context, userID string) (bool, error)
	generateMFATokenFn   func(ctx context.Context, userID string) (string, error)
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
	tokens := &mockRefreshTokenRepository{
		storeFn: func(_ context.Context, sig, userID string, _ time.Time) error {
			stored = true
			assert.Equal(t, "qf_rt_test-refresh", sig)
			assert.Equal(t, "user-1", userID)
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
			err := svc.Logout(context.Background(), "user-1", "qf_at_some-token")
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
	err := svc.Logout(context.Background(), "user-1", "qf_at_my-access-token")
	require.NoError(t, err)
	assert.Equal(t, "qf_at_my-access-token", revokedToken)
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

func TestGetMe_ReturnsStub(t *testing.T) {
	svc := newUnitService(t, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	user, err := svc.GetMe(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", user.ID)
}

// ── Breach Detection Tests ──────────────────────────────────────────────────

func TestRegister_RejectsBreachedPassword(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	breaches := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := NewService(nil, logger, audit.NopLogger{}, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{}, breaches)

	_, err := svc.Register(context.Background(), "test@example.com", "breached-password", "Test")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrPasswordBreached)
}

func TestRegister_AllowsCleanPassword(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	breaches := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return false, nil
		},
	}
	svc := NewService(nil, logger, audit.NopLogger{}, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{}, breaches)

	user, err := svc.Register(context.Background(), "test@example.com", "clean-password-12345", "Test")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)
}

func TestRegister_FailOpenOnHIBPError(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	breaches := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return false, fmt.Errorf("hibp api down")
		},
	}
	svc := NewService(nil, logger, audit.NopLogger{}, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{}, breaches)

	user, err := svc.Register(context.Background(), "test@example.com", "some-password-12345", "Test")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)
}

func TestChangePassword_RejectsBreachedPassword(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	breaches := &mockBreachChecker{
		isBreachedFn: func(_ context.Context, _ string) (bool, error) {
			return true, nil
		},
	}
	svc := NewService(nil, logger, audit.NopLogger{}, &mockUserRepository{}, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{}, breaches)

	err := svc.ChangePassword(context.Background(), "user-1", "old-pass", "breached-new-pass")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrPasswordBreached)
}

func TestLogin_SetsForcePasswordChange(t *testing.T) {
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
	result, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.NoError(t, err)
	assert.True(t, result.ForcePasswordChange, "expected ForcePasswordChange=true in login response")
}

func TestLogin_ForcePasswordChangeFalseByDefault(t *testing.T) {
	user := &domain.User{
		ID:           "user-1",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHQ$dGVzdGhhc2g",
		Roles:        []string{"user"},
	}
	users := &mockUserRepository{
		findByEmailFn: func(_ context.Context, _ string) (*domain.User, error) {
			return user, nil
		},
	}

	svc := newUnitService(t, users, &mockRefreshTokenRepository{}, &mockTokenIssuer{}, &mockHasher{})
	result, err := svc.Login(context.Background(), "alice@example.com", "correct-password")
	require.NoError(t, err)
	assert.False(t, result.ForcePasswordChange)
}
