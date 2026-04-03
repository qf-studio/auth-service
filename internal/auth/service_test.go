package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// ─── Mock implementations ────────────────────────────────────────────────────

type mockUserRepo struct {
	getByEmail      func(ctx context.Context, email string) (*domain.User, error)
	updateLastLogin func(ctx context.Context, userID string, t time.Time) error
}

func (m *mockUserRepo) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return m.getByEmail(ctx, email)
}

func (m *mockUserRepo) UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error {
	if m.updateLastLogin != nil {
		return m.updateLastLogin(ctx, userID, t)
	}
	return nil
}

type mockRefreshTokenRepo struct {
	store            func(ctx context.Context, token *domain.RefreshToken) error
	getBySignature   func(ctx context.Context, sig string) (*domain.RefreshToken, error)
	revoke           func(ctx context.Context, sig string) error
	revokeAllForUser func(ctx context.Context, userID string) error
}

func (m *mockRefreshTokenRepo) Store(ctx context.Context, token *domain.RefreshToken) error {
	return m.store(ctx, token)
}

func (m *mockRefreshTokenRepo) GetBySignature(ctx context.Context, sig string) (*domain.RefreshToken, error) {
	return m.getBySignature(ctx, sig)
}

func (m *mockRefreshTokenRepo) Revoke(ctx context.Context, sig string) error {
	return m.revoke(ctx, sig)
}

func (m *mockRefreshTokenRepo) RevokeAllForUser(ctx context.Context, userID string) error {
	return m.revokeAllForUser(ctx, userID)
}

type mockTokenProvider struct {
	generateTokenPair     func(ctx context.Context, userID string, roles []string, clientType string) (*api.AuthResult, string, error)
	validateRefreshToken  func(token string) (string, error)
	extractAccessTokenJTI func(rawToken string) (string, error)
	accessTTL             time.Duration
	refreshTTL            time.Duration
}

func (m *mockTokenProvider) GenerateTokenPair(ctx context.Context, userID string, roles []string, clientType string) (*api.AuthResult, string, error) {
	return m.generateTokenPair(ctx, userID, roles, clientType)
}

func (m *mockTokenProvider) ValidateRefreshToken(token string) (string, error) {
	return m.validateRefreshToken(token)
}

func (m *mockTokenProvider) ExtractAccessTokenJTI(rawToken string) (string, error) {
	return m.extractAccessTokenJTI(rawToken)
}

func (m *mockTokenProvider) AccessTokenTTL() time.Duration {
	if m.accessTTL == 0 {
		return 15 * time.Minute
	}
	return m.accessTTL
}

func (m *mockTokenProvider) RefreshTokenTTL() time.Duration {
	if m.refreshTTL == 0 {
		return 7 * 24 * time.Hour
	}
	return m.refreshTTL
}

type mockPasswordVerifier struct {
	verify func(password, hash string) (bool, error)
}

func (m *mockPasswordVerifier) Verify(password, hash string) (bool, error) {
	return m.verify(password, hash)
}

// ─── Test helpers ────────────────────────────────────────────────────────────

func newMiniredisService(t *testing.T) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	logger := zap.NewNop()
	svc := NewService(client, logger, nil, nil, nil, nil)
	return svc, mr
}

type testDeps struct {
	users     *mockUserRepo
	refresh   *mockRefreshTokenRepo
	tokens    *mockTokenProvider
	passwords *mockPasswordVerifier
}

func newTestServiceWithMocks(t *testing.T) (*Service, *miniredis.Miniredis, *testDeps) {
	t.Helper()

	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })

	deps := &testDeps{
		users:     &mockUserRepo{},
		refresh:   &mockRefreshTokenRepo{},
		tokens:    &mockTokenProvider{},
		passwords: &mockPasswordVerifier{},
	}

	logger := zap.NewNop()
	svc := NewService(client, logger, deps.users, deps.refresh, deps.tokens, deps.passwords)
	return svc, mr, deps
}

var testAuthResult = &api.AuthResult{
	AccessToken:  "qf_at_test-access-token",
	RefreshToken: "qf_rt_test-refresh-token",
	TokenType:    "Bearer",
	ExpiresIn:    900,
}

func activeUser() *domain.User {
	return &domain.User{
		ID:           "user-123",
		Email:        "alice@example.com",
		PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$salt$hash",
		Status:       domain.UserStatusActive,
		Roles:        []string{"user"},
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}
}

// ─── Login tests ─────────────────────────────────────────────────────────────

func TestLogin(t *testing.T) {
	tests := []struct {
		name      string
		email     string
		password  string
		setup     func(*testDeps)
		wantErr   error
		wantNil   bool
		checkSig  bool // verify refresh token was stored
	}{
		{
			name:     "success",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, email string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return testAuthResult, "refresh-sig-abc", nil
				}
				d.refresh.store = func(_ context.Context, _ *domain.RefreshToken) error {
					return nil
				}
			},
			checkSig: true,
		},
		{
			name:     "user not found returns generic error",
			email:    "nobody@example.com",
			password: "any-password-12345678",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return nil, api.ErrNotFound
				}
			},
			wantErr: ErrInvalidCredentials,
			wantNil: true,
		},
		{
			name:     "wrong password returns generic error",
			email:    "alice@example.com",
			password: "wrong-password-12345678",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return false, nil
				}
			},
			wantErr: ErrInvalidCredentials,
			wantNil: true,
		},
		{
			name:     "locked account",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				u := activeUser()
				u.Status = domain.UserStatusLocked
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return u, nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
			},
			wantErr: ErrAccountLocked,
			wantNil: true,
		},
		{
			name:     "suspended account",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				u := activeUser()
				u.Status = domain.UserStatusSuspended
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return u, nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
			},
			wantErr: ErrAccountSuspended,
			wantNil: true,
		},
		{
			name:     "password verification internal error",
			email:    "alice@example.com",
			password: "any-password-123456789",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return false, errors.New("argon2 internal failure")
				}
			},
			wantNil: true,
		},
		{
			name:     "token generation error",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return nil, "", errors.New("key not loaded")
				}
			},
			wantNil: true,
		},
		{
			name:     "refresh token store error",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return testAuthResult, "sig", nil
				}
				d.refresh.store = func(_ context.Context, _ *domain.RefreshToken) error {
					return errors.New("db connection lost")
				}
			},
			wantNil: true,
		},
		{
			name:     "UpdateLastLoginAt failure does not fail login",
			email:    "alice@example.com",
			password: "correct-password-12345",
			setup: func(d *testDeps) {
				d.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
					return activeUser(), nil
				}
				d.passwords.verify = func(_, _ string) (bool, error) {
					return true, nil
				}
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return testAuthResult, "sig", nil
				}
				d.refresh.store = func(_ context.Context, _ *domain.RefreshToken) error {
					return nil
				}
				d.users.updateLastLogin = func(_ context.Context, _ string, _ time.Time) error {
					return errors.New("db timeout")
				}
			},
			checkSig: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, deps := newTestServiceWithMocks(t)
			tt.setup(deps)

			result, err := svc.Login(context.Background(), tt.email, tt.password)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			}
			if tt.wantNil {
				assert.Nil(t, result)
			}
			if tt.checkSig {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, testAuthResult.AccessToken, result.AccessToken)
				assert.Equal(t, testAuthResult.RefreshToken, result.RefreshToken)
				assert.Equal(t, "Bearer", result.TokenType)
			}
		})
	}
}

func TestLogin_SameErrorForNotFoundAndWrongPassword(t *testing.T) {
	// Verify that "not found" and "wrong password" produce the exact same error
	// to prevent user enumeration.
	svc, _, deps := newTestServiceWithMocks(t)

	deps.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
		return nil, api.ErrNotFound
	}
	_, errNotFound := svc.Login(context.Background(), "x@y.com", "pw1234567890abcde")
	require.Error(t, errNotFound)

	deps.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
		return activeUser(), nil
	}
	deps.passwords.verify = func(_, _ string) (bool, error) { return false, nil }
	_, errWrong := svc.Login(context.Background(), "x@y.com", "pw1234567890abcde")
	require.Error(t, errWrong)

	assert.ErrorIs(t, errNotFound, ErrInvalidCredentials)
	assert.ErrorIs(t, errWrong, ErrInvalidCredentials)
}

func TestLogin_StoresRefreshTokenWithCorrectFields(t *testing.T) {
	svc, _, deps := newTestServiceWithMocks(t)
	var stored *domain.RefreshToken

	deps.users.getByEmail = func(_ context.Context, _ string) (*domain.User, error) {
		return activeUser(), nil
	}
	deps.passwords.verify = func(_, _ string) (bool, error) { return true, nil }
	deps.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
		return testAuthResult, "the-refresh-sig", nil
	}
	deps.tokens.refreshTTL = 24 * time.Hour
	deps.refresh.store = func(_ context.Context, tok *domain.RefreshToken) error {
		stored = tok
		return nil
	}

	_, err := svc.Login(context.Background(), "alice@example.com", "correct-password-12345")
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, "the-refresh-sig", stored.Signature)
	assert.Equal(t, "user-123", stored.UserID)
	assert.WithinDuration(t, time.Now().Add(24*time.Hour), stored.ExpiresAt, 5*time.Second)
	assert.Nil(t, stored.RevokedAt)
}

// ─── RefreshTokens tests ────────────────────────────────────────────────────

func TestRefreshTokens(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name    string
		token   string
		setup   func(*testDeps)
		wantErr error
		wantNil bool
	}{
		{
			name:  "success with token rotation",
			token: "qf_rt_valid-refresh-token",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "old-sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return &domain.RefreshToken{
						Signature: "old-sig",
						UserID:    "user-123",
						ExpiresAt: now.Add(24 * time.Hour),
						CreatedAt: now.Add(-1 * time.Hour),
					}, nil
				}
				d.refresh.revoke = func(_ context.Context, sig string) error {
					assert.Equal(t, "old-sig", sig)
					return nil
				}
				d.tokens.generateTokenPair = func(_ context.Context, userID string, _ []string, _ string) (*api.AuthResult, string, error) {
					assert.Equal(t, "user-123", userID)
					return testAuthResult, "new-sig", nil
				}
				d.refresh.store = func(_ context.Context, tok *domain.RefreshToken) error {
					assert.Equal(t, "new-sig", tok.Signature)
					assert.Equal(t, "user-123", tok.UserID)
					return nil
				}
			},
		},
		{
			name:  "invalid refresh token format",
			token: "garbage",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "", errors.New("invalid HMAC")
				}
			},
			wantErr: api.ErrUnauthorized,
			wantNil: true,
		},
		{
			name:  "token not found in DB",
			token: "qf_rt_unknown-token",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "unknown-sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return nil, api.ErrNotFound
				}
			},
			wantErr: api.ErrUnauthorized,
			wantNil: true,
		},
		{
			name:  "expired token",
			token: "qf_rt_expired-token",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "expired-sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return &domain.RefreshToken{
						Signature: "expired-sig",
						UserID:    "user-123",
						ExpiresAt: now.Add(-1 * time.Hour), // expired
						CreatedAt: now.Add(-8 * 24 * time.Hour),
					}, nil
				}
			},
			wantErr: ErrTokenExpired,
			wantNil: true,
		},
		{
			name:  "revoked token triggers reuse detection",
			token: "qf_rt_revoked-token",
			setup: func(d *testDeps) {
				revokedAt := now.Add(-30 * time.Minute)
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "revoked-sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return &domain.RefreshToken{
						Signature: "revoked-sig",
						UserID:    "user-456",
						ExpiresAt: now.Add(24 * time.Hour),
						RevokedAt: &revokedAt,
						CreatedAt: now.Add(-1 * time.Hour),
					}, nil
				}
				var revokedAll bool
				d.refresh.revokeAllForUser = func(_ context.Context, userID string) error {
					assert.Equal(t, "user-456", userID)
					revokedAll = true
					return nil
				}
				t.Cleanup(func() {
					assert.True(t, revokedAll, "expected RevokeAllForUser to be called on reuse detection")
				})
			},
			wantErr: ErrTokenRevoked,
			wantNil: true,
		},
		{
			name:  "token generation error during refresh",
			token: "qf_rt_valid-token",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return &domain.RefreshToken{
						Signature: "sig",
						UserID:    "user-123",
						ExpiresAt: now.Add(24 * time.Hour),
						CreatedAt: now.Add(-1 * time.Hour),
					}, nil
				}
				d.refresh.revoke = func(_ context.Context, _ string) error { return nil }
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return nil, "", errors.New("signing key unavailable")
				}
			},
			wantNil: true,
		},
		{
			name:  "store error during refresh",
			token: "qf_rt_valid-token",
			setup: func(d *testDeps) {
				d.tokens.validateRefreshToken = func(_ string) (string, error) {
					return "sig", nil
				}
				d.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
					return &domain.RefreshToken{
						Signature: "sig",
						UserID:    "user-123",
						ExpiresAt: now.Add(24 * time.Hour),
						CreatedAt: now.Add(-1 * time.Hour),
					}, nil
				}
				d.refresh.revoke = func(_ context.Context, _ string) error { return nil }
				d.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
					return testAuthResult, "new-sig", nil
				}
				d.refresh.store = func(_ context.Context, _ *domain.RefreshToken) error {
					return errors.New("db error")
				}
			},
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, deps := newTestServiceWithMocks(t)
			tt.setup(deps)

			result, err := svc.RefreshTokens(context.Background(), tt.token)

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
			}
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, testAuthResult.AccessToken, result.AccessToken)
		})
	}
}

func TestRefreshTokens_RotationStoresNewToken(t *testing.T) {
	svc, _, deps := newTestServiceWithMocks(t)
	now := time.Now()

	var storedNew *domain.RefreshToken
	var revokedSig string

	deps.tokens.validateRefreshToken = func(_ string) (string, error) {
		return "old-sig", nil
	}
	deps.tokens.refreshTTL = 7 * 24 * time.Hour
	deps.refresh.getBySignature = func(_ context.Context, _ string) (*domain.RefreshToken, error) {
		return &domain.RefreshToken{
			Signature: "old-sig",
			UserID:    "user-789",
			ExpiresAt: now.Add(24 * time.Hour),
			CreatedAt: now.Add(-6 * 24 * time.Hour),
		}, nil
	}
	deps.refresh.revoke = func(_ context.Context, sig string) error {
		revokedSig = sig
		return nil
	}
	deps.tokens.generateTokenPair = func(_ context.Context, _ string, _ []string, _ string) (*api.AuthResult, string, error) {
		return testAuthResult, "brand-new-sig", nil
	}
	deps.refresh.store = func(_ context.Context, tok *domain.RefreshToken) error {
		storedNew = tok
		return nil
	}

	result, err := svc.RefreshTokens(context.Background(), "qf_rt_old-token")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "old-sig", revokedSig, "old token should be revoked")
	require.NotNil(t, storedNew)
	assert.Equal(t, "brand-new-sig", storedNew.Signature)
	assert.Equal(t, "user-789", storedNew.UserID)
	assert.WithinDuration(t, now.Add(7*24*time.Hour), storedNew.ExpiresAt, 5*time.Second)
}

// ─── Logout tests ────────────────────────────────────────────────────────────

func TestLogout(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		setup   func(*testDeps)
		wantErr bool
		checkJTI string
	}{
		{
			name:  "success blocklists JTI in redis",
			token: "qf_at_some-access-token",
			setup: func(d *testDeps) {
				d.tokens.extractAccessTokenJTI = func(_ string) (string, error) {
					return "jti-abc-123", nil
				}
			},
			checkJTI: "jti-abc-123",
		},
		{
			name:  "invalid token returns error",
			token: "garbage-token",
			setup: func(d *testDeps) {
				d.tokens.extractAccessTokenJTI = func(_ string) (string, error) {
					return "", errors.New("cannot parse")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, mr, deps := newTestServiceWithMocks(t)
			tt.setup(deps)

			err := svc.Logout(context.Background(), "user-123", tt.token)

			if tt.wantErr {
				require.Error(t, err)
				assert.ErrorIs(t, err, api.ErrUnauthorized)
				return
			}
			require.NoError(t, err)

			if tt.checkJTI != "" {
				val, err := mr.Get(tokenBlockPrefix + tt.checkJTI)
				require.NoError(t, err)
				assert.Equal(t, "1", val)

				assert.True(t, mr.Exists(tokenBlockPrefix+tt.checkJTI),
					"blocklist key should exist in Redis")
			}
		})
	}
}

func TestLogout_BlocklistTTL(t *testing.T) {
	svc, mr, deps := newTestServiceWithMocks(t)

	deps.tokens.extractAccessTokenJTI = func(_ string) (string, error) {
		return "jti-ttl-check", nil
	}
	deps.tokens.accessTTL = 10 * time.Minute

	err := svc.Logout(context.Background(), "user-123", "qf_at_token")
	require.NoError(t, err)

	ttl := mr.TTL(tokenBlockPrefix + "jti-ttl-check")
	assert.True(t, ttl > 0 && ttl <= 10*time.Minute,
		"expected blocklist TTL in (0, 10m], got %v", ttl)
}

// ─── LogoutAll tests ─────────────────────────────────────────────────────────

func TestLogoutAll(t *testing.T) {
	tests := []struct {
		name    string
		userID  string
		setup   func(*testDeps)
		wantErr bool
	}{
		{
			name:   "success revokes all refresh tokens",
			userID: "user-123",
			setup: func(d *testDeps) {
				var called bool
				d.refresh.revokeAllForUser = func(_ context.Context, userID string) error {
					called = true
					assert.Equal(t, "user-123", userID)
					return nil
				}
				t.Cleanup(func() {
					assert.True(t, called, "expected RevokeAllForUser to be called")
				})
			},
		},
		{
			name:   "repository error propagates",
			userID: "user-456",
			setup: func(d *testDeps) {
				d.refresh.revokeAllForUser = func(_ context.Context, _ string) error {
					return errors.New("db unavailable")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, _, deps := newTestServiceWithMocks(t)
			tt.setup(deps)

			err := svc.LogoutAll(context.Background(), tt.userID)

			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
		})
	}
}

// ─── Password Reset tests (migrated to miniredis) ───────────────────────────

func TestResetPassword_StoresTokenInRedis(t *testing.T) {
	svc, mr := newMiniredisService(t)
	ctx := context.Background()

	err := svc.ResetPassword(ctx, "user@example.com")
	require.NoError(t, err)

	keys := mr.Keys()

	var resetKeys []string
	for _, k := range keys {
		if len(k) > len(resetTokenPrefix) && k[:len(resetTokenPrefix)] == resetTokenPrefix {
			resetKeys = append(resetKeys, k)
		}
	}
	require.Len(t, resetKeys, 1, "expected exactly one reset token in Redis")

	email, err := mr.Get(resetKeys[0])
	require.NoError(t, err)
	assert.Equal(t, "user@example.com", email)
}

func TestConfirmPasswordReset_ValidToken(t *testing.T) {
	svc, mr := newMiniredisService(t)
	ctx := context.Background()

	token := "test-reset-token-abc123"
	key := resetTokenPrefix + token
	require.NoError(t, mr.Set(key, "user@example.com"))

	err := svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	assert.False(t, mr.Exists(key), "token should be deleted after confirmation")
}

func TestConfirmPasswordReset_InvalidToken(t *testing.T) {
	svc, _ := newMiniredisService(t)
	ctx := context.Background()

	err := svc.ConfirmPasswordReset(ctx, "nonexistent-token", "new-secure-password-12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestConfirmPasswordReset_TokenUsedOnce(t *testing.T) {
	svc, mr := newMiniredisService(t)
	ctx := context.Background()

	token := "one-time-token"
	key := resetTokenPrefix + token
	require.NoError(t, mr.Set(key, "user@example.com"))

	err := svc.ConfirmPasswordReset(ctx, token, "new-secure-password-12345")
	require.NoError(t, err)

	err = svc.ConfirmPasswordReset(ctx, token, "another-password-67890")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
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
	svc, _ := newMiniredisService(t)
	user, err := svc.Register(context.Background(), "test@example.com", "password123456789", "Test")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test", user.Name)
	assert.NotEmpty(t, user.ID)
}

func TestGetMe_ReturnsStub(t *testing.T) {
	svc, _ := newMiniredisService(t)
	user, err := svc.GetMe(context.Background(), "user-42")
	require.NoError(t, err)
	assert.Equal(t, "user-42", user.ID)
}
