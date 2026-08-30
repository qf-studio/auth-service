package admin_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
	"github.com/qf-studio/auth-service/internal/token"

	authpkg "github.com/qf-studio/auth-service/internal/auth"
)

// fakeRefreshTokenRepository is a thread-safe, map-backed implementation of
// storage.RefreshTokenRepository (via mocks.MockRefreshTokenRepository) used
// to wire token.Service, auth.Service, and admin.TokenService together in
// this test so they observe the same Postgres-side state, the way they do
// through the real repository in production.
type fakeRefreshTokenRepository struct {
	mu      sync.Mutex
	records map[string]*domain.RefreshTokenRecord
}

func newFakeRefreshTokenRepository() *mocks.MockRefreshTokenRepository {
	f := &fakeRefreshTokenRepository{records: make(map[string]*domain.RefreshTokenRecord)}

	return &mocks.MockRefreshTokenRepository{
		StoreFn: func(_ context.Context, tenantID uuid.UUID, signature, userID string, expiresAt time.Time) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			f.records[signature] = &domain.RefreshTokenRecord{
				Signature: signature,
				TenantID:  tenantID,
				UserID:    userID,
				ExpiresAt: expiresAt,
				CreatedAt: time.Now(),
			}
			return nil
		},
		FindBySignatureFn: func(_ context.Context, _ uuid.UUID, signature string) (*domain.RefreshTokenRecord, error) {
			f.mu.Lock()
			defer f.mu.Unlock()
			rec, ok := f.records[signature]
			if !ok {
				return nil, assertNotFoundErr
			}
			return rec, nil
		},
		RevokeFn: func(_ context.Context, _ uuid.UUID, signature string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			rec, ok := f.records[signature]
			if !ok {
				return nil
			}
			now := time.Now()
			rec.RevokedAt = &now
			return nil
		},
		RevokeAllForUserFn: func(_ context.Context, _ uuid.UUID, userID string) error {
			f.mu.Lock()
			defer f.mu.Unlock()
			now := time.Now()
			for _, rec := range f.records {
				if rec.UserID == userID {
					rec.RevokedAt = &now
				}
			}
			return nil
		},
	}
}

var assertNotFoundErr = errNotFound{}

type errNotFound struct{}

func (errNotFound) Error() string { return "refresh token record not found" }

// TestRefreshTokenIntrospectionFlow is the GH-486 end-to-end acceptance test:
// login mints a refresh token whose signature is correctly persisted to
// Postgres (not the full token), introspection reflects it as active with the
// right sub/exp/iat, rotation revokes the old signature's row and persists
// the new one so introspection tracks the rotation immediately, and logout
// revokes the current refresh token's row so introspection reflects it too.
func TestRefreshTokenIntrospectionFlow(t *testing.T) {
	ctx := context.Background()

	// ── Redis (shared by token.Service for its hot-path state) ──
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	// ── Signing key + token.Service ──
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	oidcCfg := config.OIDCConfig{
		IssuerURL:  "https://auth.qf.studio",
		IDTokenTTL: time.Hour,
	}

	tokenSvc, err := token.NewServiceFromKey(jwtCfg, oidcCfg, key, rc, zap.NewNop(), audit.NopLogger{})
	require.NoError(t, err)

	// ── Shared fake Postgres-backed refresh token repository ──
	refreshRepo := newFakeRefreshTokenRepository()
	tokenSvc.SetRefreshTokenStore(refreshRepo)

	// ── auth.Service ──
	hasher := password.New(nil)
	passwordHash, err := hasher.Hash("correct horse battery staple")
	require.NoError(t, err)

	user := &domain.User{
		ID:           "user-1",
		TenantID:     domain.DefaultTenantID,
		Email:        "test@example.com",
		PasswordHash: passwordHash,
		Roles:        []string{"user"},
	}

	userRepo := &mocks.MockUserRepository{
		FindByEmailFn: func(_ context.Context, _ uuid.UUID, email string) (*domain.User, error) {
			if email == user.Email {
				return user, nil
			}
			return nil, assertNotFoundErr
		},
		UpdateLastLoginFn: func(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
			return nil
		},
	}

	authSvc := authpkg.NewService(authpkg.ServiceDeps{
		Redis:           rc,
		Logger:          zap.NewNop(),
		Auditor:         audit.NopLogger{},
		Users:           userRepo,
		Tokens:          refreshRepo,
		Issuer:          tokenSvc,
		Hasher:          hasher,
		RefreshTokenTTL: jwtCfg.RefreshTokenTTL,
	})

	// ── admin.TokenService (introspection) ──
	adminTokenSvc := admin.NewTokenService(tokenSvc, refreshRepo, oidcCfg.IssuerURL, zap.NewNop(), audit.NopLogger{})

	// ── Step 1: login ──
	loginResult, err := authSvc.Login(ctx, user.Email, "correct horse battery staple")
	require.NoError(t, err)
	require.NotEmpty(t, loginResult.RefreshToken)
	require.NotEmpty(t, loginResult.AccessToken)

	// ── Step 2: introspect the freshly minted refresh token ──
	introspectResp, err := adminTokenSvc.Introspect(ctx, loginResult.RefreshToken)
	require.NoError(t, err)
	assert.True(t, introspectResp.Active, "freshly issued refresh token should introspect active")
	assert.Equal(t, user.ID, introspectResp.Sub)
	assert.NotZero(t, introspectResp.Exp)
	assert.NotZero(t, introspectResp.Iat)
	assert.Greater(t, introspectResp.Exp, introspectResp.Iat)

	oldRefreshToken := loginResult.RefreshToken

	// ── Step 3: refresh (rotate) ──
	refreshResult, err := tokenSvc.Refresh(ctx, oldRefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refreshResult.RefreshToken)
	assert.NotEqual(t, oldRefreshToken, refreshResult.RefreshToken, "rotation should mint a new refresh token")

	// Old refresh token must no longer introspect as active.
	oldIntrospectResp, err := adminTokenSvc.Introspect(ctx, oldRefreshToken)
	require.NoError(t, err)
	assert.False(t, oldIntrospectResp.Active, "rotated-away refresh token should introspect inactive immediately")

	// New refresh token must introspect as active.
	newIntrospectResp, err := adminTokenSvc.Introspect(ctx, refreshResult.RefreshToken)
	require.NoError(t, err)
	assert.True(t, newIntrospectResp.Active, "newly rotated refresh token should introspect active")
	assert.Equal(t, user.ID, newIntrospectResp.Sub)
	assert.NotZero(t, newIntrospectResp.Exp)
	assert.NotZero(t, newIntrospectResp.Iat)

	// ── Step 4: logout ──
	err = authSvc.Logout(ctx, user.ID, refreshResult.AccessToken, refreshResult.RefreshToken)
	require.NoError(t, err)

	loggedOutIntrospectResp, err := adminTokenSvc.Introspect(ctx, refreshResult.RefreshToken)
	require.NoError(t, err)
	assert.False(t, loggedOutIntrospectResp.Active, "refresh token should introspect inactive after logout")
}
