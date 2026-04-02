package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	redispkg "github.com/qf-studio/auth-service/internal/redis"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Mocks ---

type mockUserRepo struct {
	users map[string]mockUser // email -> user
	// Track calls for assertions.
	updatedUserID string
	updatedHash   string
	updateErr     error
}

type mockUser struct {
	id           string
	passwordHash string
}

func newMockUserRepo() *mockUserRepo {
	return &mockUserRepo{
		users: make(map[string]mockUser),
	}
}

func (m *mockUserRepo) GetByEmail(_ context.Context, email string) (string, string, error) {
	u, ok := m.users[email]
	if !ok {
		return "", "", ErrUserNotFound
	}
	return u.id, u.passwordHash, nil
}

func (m *mockUserRepo) UpdatePasswordHash(_ context.Context, userID string, newHash string) error {
	m.updatedUserID = userID
	m.updatedHash = newHash
	if m.updateErr != nil {
		return m.updateErr
	}
	return nil
}

type mockTokenStore struct {
	store    map[string]storedToken
	storeErr error
}

type storedToken struct {
	value string
	ttl   time.Duration
}

func newMockTokenStore() *mockTokenStore {
	return &mockTokenStore{
		store: make(map[string]storedToken),
	}
}

func (m *mockTokenStore) Store(_ context.Context, tokenID string, hashedToken string, ttl time.Duration) error {
	if m.storeErr != nil {
		return m.storeErr
	}
	m.store[tokenID] = storedToken{value: hashedToken, ttl: ttl}
	return nil
}

func (m *mockTokenStore) Retrieve(_ context.Context, tokenID string) (string, error) {
	t, ok := m.store[tokenID]
	if !ok {
		return "", redispkg.ErrTokenNotFound
	}
	return t.value, nil
}

func (m *mockTokenStore) Delete(_ context.Context, tokenID string) error {
	if _, ok := m.store[tokenID]; !ok {
		return redispkg.ErrTokenNotFound
	}
	delete(m.store, tokenID)
	return nil
}

type mockRateLimiter struct {
	remaining int
	err       error
}

func (m *mockRateLimiter) Allow(_ context.Context, _ string) (int, error) {
	return m.remaining, m.err
}

type mockRevoker struct {
	revokedUserID string
	err           error
}

func (m *mockRevoker) RevokeAllForUser(_ context.Context, userID string) error {
	m.revokedUserID = userID
	return m.err
}

// --- Helper ---

func newTestService(users *mockUserRepo, tokens *mockTokenStore, limiter *mockRateLimiter, revoker *mockRevoker) *Service {
	return &Service{
		users:   users,
		tokens:  tokens,
		limiter: limiter,
		revoker: revoker,
		devMode: false,
	}
}

// --- RequestPasswordReset tests ---

func TestRequestPasswordReset(t *testing.T) {
	tests := []struct {
		name        string
		email       string
		setupUsers  map[string]mockUser
		limiterRem  int
		limiterErr  error
		tokenStoreErr error
		wantErr     error
		wantStored  bool
	}{
		{
			name:  "existing user — token stored",
			email: "user@example.com",
			setupUsers: map[string]mockUser{
				"user@example.com": {id: "user-1", passwordHash: "hash"},
			},
			limiterRem: 2,
			wantStored: true,
		},
		{
			name:       "non-existing user — silent success",
			email:      "nobody@example.com",
			setupUsers: map[string]mockUser{},
			limiterRem: 2,
			wantStored: false,
		},
		{
			name:  "rate limited — silent success",
			email: "user@example.com",
			setupUsers: map[string]mockUser{
				"user@example.com": {id: "user-1", passwordHash: "hash"},
			},
			limiterErr: redispkg.ErrRateLimited,
			wantStored: false,
		},
		{
			name:  "rate limiter internal error — silent success",
			email: "user@example.com",
			setupUsers: map[string]mockUser{
				"user@example.com": {id: "user-1", passwordHash: "hash"},
			},
			limiterErr: errors.New("redis connection error"),
			wantStored: false,
		},
		{
			name:  "token store error — silent success",
			email: "user@example.com",
			setupUsers: map[string]mockUser{
				"user@example.com": {id: "user-1", passwordHash: "hash"},
			},
			limiterRem:    2,
			tokenStoreErr: errors.New("redis write error"),
			wantStored:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := newMockUserRepo()
			users.users = tt.setupUsers
			tokens := newMockTokenStore()
			tokens.storeErr = tt.tokenStoreErr
			limiter := &mockRateLimiter{remaining: tt.limiterRem, err: tt.limiterErr}
			revoker := &mockRevoker{}

			svc := newTestService(users, tokens, limiter, revoker)
			err := svc.RequestPasswordReset(context.Background(), tt.email)

			// Always returns nil to prevent enumeration.
			assert.NoError(t, err)

			if tt.wantStored {
				assert.Len(t, tokens.store, 1, "expected one token stored")
				// Verify the stored value is the user ID.
				for _, v := range tokens.store {
					assert.Equal(t, tt.setupUsers[tt.email].id, v.value)
					assert.Equal(t, resetTokenTTL, v.ttl)
				}
			} else {
				assert.Empty(t, tokens.store, "expected no token stored")
			}
		})
	}
}

func TestRequestPasswordReset_TokenFormat(t *testing.T) {
	users := newMockUserRepo()
	users.users = map[string]mockUser{
		"user@example.com": {id: "user-1", passwordHash: "hash"},
	}
	tokens := newMockTokenStore()
	limiter := &mockRateLimiter{remaining: 2}
	revoker := &mockRevoker{}

	svc := &Service{
		users:   users,
		tokens:  tokens,
		limiter: limiter,
		revoker: revoker,
		devMode: true, // Enable dev mode to verify token is logged.
	}

	err := svc.RequestPasswordReset(context.Background(), "user@example.com")
	require.NoError(t, err)
	require.Len(t, tokens.store, 1)

	// The stored key should be a hex-encoded SHA-256 hash (64 chars).
	for k := range tokens.store {
		assert.Len(t, k, 64, "token ID should be SHA-256 hex (64 chars)")
	}
}

// --- ConfirmPasswordReset tests ---

func TestConfirmPasswordReset(t *testing.T) {
	validPassword := "this-is-a-secure-password-123"
	weakPassword := "short"

	// Helper to store a token in the mock store and return the raw token string.
	storeToken := func(ts *mockTokenStore, userID string) string {
		rawToken := resetTokenPrefix + "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
		h := sha256.Sum256([]byte(rawToken))
		tokenHash := hex.EncodeToString(h[:])
		ts.store[tokenHash] = storedToken{value: userID, ttl: resetTokenTTL}
		return rawToken
	}

	tests := []struct {
		name        string
		setupToken  bool
		userID      string
		password    string
		updateErr   error
		revokerErr  error
		wantErr     error
		wantUpdated bool
		wantRevoked bool
	}{
		{
			name:        "valid token and password — success",
			setupToken:  true,
			userID:      "user-1",
			password:    validPassword,
			wantUpdated: true,
			wantRevoked: true,
		},
		{
			name:     "expired/invalid token — error",
			password: validPassword,
			wantErr:  ErrInvalidResetToken,
		},
		{
			name:       "valid token but weak password — error",
			setupToken: true,
			userID:     "user-1",
			password:   weakPassword,
			wantErr:    ErrWeakPassword,
		},
		{
			name:        "valid token — DB update error propagates",
			setupToken:  true,
			userID:      "user-1",
			password:    validPassword,
			updateErr:   errors.New("db connection error"),
			wantErr:     errors.New("update password"),
			wantUpdated: false,
		},
		{
			name:        "valid token — revoker error is non-fatal",
			setupToken:  true,
			userID:      "user-1",
			password:    validPassword,
			revokerErr:  errors.New("revocation failed"),
			wantUpdated: true,
			wantRevoked: false, // Error logged, not propagated.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			users := newMockUserRepo()
			users.updateErr = tt.updateErr
			tokens := newMockTokenStore()
			limiter := &mockRateLimiter{remaining: 2}
			revoker := &mockRevoker{err: tt.revokerErr}

			svc := newTestService(users, tokens, limiter, revoker)

			var rawToken string
			if tt.setupToken {
				rawToken = storeToken(tokens, tt.userID)
			} else {
				rawToken = "qf_pr_nonexistent_token_value"
			}

			err := svc.ConfirmPasswordReset(context.Background(), rawToken, tt.password)

			if tt.wantErr != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErr, ErrInvalidResetToken) || errors.Is(tt.wantErr, ErrWeakPassword) {
					assert.ErrorIs(t, err, tt.wantErr)
				} else {
					assert.Contains(t, err.Error(), tt.wantErr.Error())
				}
				return
			}

			require.NoError(t, err)

			if tt.wantUpdated {
				assert.Equal(t, tt.userID, users.updatedUserID)
				assert.NotEmpty(t, users.updatedHash)
				// Verify the hash is valid Argon2id format.
				assert.True(t, strings.HasPrefix(users.updatedHash, "$argon2id$"))
			}

			if tt.wantRevoked {
				assert.Equal(t, tt.userID, revoker.revokedUserID)
			}

			// Token should be deleted after successful confirm.
			if tt.setupToken {
				assert.Empty(t, tokens.store, "token should be deleted after use")
			}
		})
	}
}

func TestConfirmPasswordReset_TokenCannotBeReused(t *testing.T) {
	tokens := newMockTokenStore()
	users := newMockUserRepo()
	limiter := &mockRateLimiter{remaining: 2}
	revoker := &mockRevoker{}
	svc := newTestService(users, tokens, limiter, revoker)

	// Store a token manually.
	rawToken := resetTokenPrefix + "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
	h := sha256.Sum256([]byte(rawToken))
	tokenHash := hex.EncodeToString(h[:])
	tokens.store[tokenHash] = storedToken{value: "user-1", ttl: resetTokenTTL}

	password := "this-is-a-secure-password-123"

	// First use succeeds.
	err := svc.ConfirmPasswordReset(context.Background(), rawToken, password)
	require.NoError(t, err)

	// Second use fails — token was deleted.
	err = svc.ConfirmPasswordReset(context.Background(), rawToken, password)
	assert.ErrorIs(t, err, ErrInvalidResetToken)
}

// --- Password hashing tests ---

func TestHashPassword(t *testing.T) {
	hash, err := HashPassword("test-password-long-enough")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(hash, "$argon2id$v="))
	assert.Contains(t, hash, "m=19456,t=2,p=1")
}

func TestVerifyPassword(t *testing.T) {
	password := "my-secure-password-here"
	hash, err := HashPassword(password)
	require.NoError(t, err)

	ok, err := VerifyPassword(password, hash)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = VerifyPassword("wrong-password-attempt", hash)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyPassword_InvalidFormats(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"no dollar signs", "not-a-valid-hash"},
		{"wrong algorithm", "$bcrypt$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA"},
		{"bad params", "$argon2id$v=19$garbage$c2FsdA$aGFzaA"},
		{"bad salt base64", "$argon2id$v=19$m=19456,t=2,p=1$!!!invalid!!!$aGFzaA"},
		{"bad hash base64", "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$!!!invalid!!!"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := VerifyPassword("password", tt.encoded)
			assert.Error(t, err)
		})
	}
}

func TestNewService(t *testing.T) {
	users := newMockUserRepo()
	tokens := newMockTokenStore()
	limiter := &mockRateLimiter{}
	revoker := &mockRevoker{}

	svc := NewService(users, tokens, limiter, revoker)
	assert.NotNil(t, svc)
	assert.Equal(t, users, svc.users)
	assert.Equal(t, tokens, svc.tokens)
	assert.Equal(t, limiter, svc.limiter)
	assert.Equal(t, revoker, svc.revoker)
}

func TestRequestPasswordReset_UserLookupInternalError(t *testing.T) {
	// When the user repo returns a non-ErrUserNotFound error, it should still return nil.
	users := &failingUserRepo{err: errors.New("database timeout")}
	tokens := newMockTokenStore()
	limiter := &mockRateLimiter{remaining: 2}
	revoker := &mockRevoker{}

	svc := &Service{users: users, tokens: tokens, limiter: limiter, revoker: revoker}

	err := svc.RequestPasswordReset(context.Background(), "user@example.com")
	assert.NoError(t, err)
	assert.Empty(t, tokens.store)
}

// failingUserRepo always returns an error on GetByEmail.
type failingUserRepo struct {
	err error
}

func (f *failingUserRepo) GetByEmail(_ context.Context, _ string) (string, string, error) {
	return "", "", f.err
}

func (f *failingUserRepo) UpdatePasswordHash(_ context.Context, _ string, _ string) error {
	return nil
}

func TestConfirmPasswordReset_RetrieveError(t *testing.T) {
	// Non-ErrTokenNotFound error from token store should propagate.
	tokens := &failingTokenStore{retrieveErr: errors.New("redis timeout")}
	users := newMockUserRepo()
	limiter := &mockRateLimiter{remaining: 2}
	revoker := &mockRevoker{}

	svc := &Service{users: users, tokens: tokens, limiter: limiter, revoker: revoker}

	err := svc.ConfirmPasswordReset(context.Background(), "qf_pr_sometoken", "this-is-a-secure-password-123")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "retrieve reset token")
}

// failingTokenStore simulates token store errors.
type failingTokenStore struct {
	retrieveErr error
}

func (f *failingTokenStore) Store(_ context.Context, _ string, _ string, _ time.Duration) error {
	return nil
}

func (f *failingTokenStore) Retrieve(_ context.Context, _ string) (string, error) {
	return "", f.retrieveErr
}

func (f *failingTokenStore) Delete(_ context.Context, _ string) error {
	return nil
}

func TestSha256Hash(t *testing.T) {
	// Verify deterministic hashing.
	h1 := sha256Hash("test-input")
	h2 := sha256Hash("test-input")
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // hex-encoded SHA-256 is 64 chars.

	// Different input produces different hash.
	h3 := sha256Hash("different-input")
	assert.NotEqual(t, h1, h3)
}

func TestHashPassword_UniquePerCall(t *testing.T) {
	// Same password should produce different hashes (different salt each time).
	h1, err := HashPassword("same-password-for-both")
	require.NoError(t, err)
	h2, err := HashPassword("same-password-for-both")
	require.NoError(t, err)
	assert.NotEqual(t, h1, h2)
}
