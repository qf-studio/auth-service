package session_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/auth"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/session"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
	"github.com/qf-studio/auth-service/internal/token"
)

// newTerminateAllEnv wires the real token service, auth service (LogoutAll),
// Redis session store and HTTP router the way cmd/server does, over one
// miniredis.
func newTerminateAllEnv(t *testing.T) (tokenSvc *token.Service, sessionSvc *session.Service, router *gin.Engine) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	jwtCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret-1"},
	}
	oidcCfg := config.OIDCConfig{IssuerURL: "https://auth.test.invalid", IDTokenTTL: time.Hour}
	log := zap.NewNop()
	tokenSvc, err = token.NewServiceFromKey(jwtCfg, oidcCfg, key, rc, log, audit.NopLogger{})
	require.NoError(t, err)

	// Postgres bookkeeping is out of scope here; the Redis revocation inside
	// the wrapper is what decides whether a refresh token still works.
	pgTokens := &mocks.MockRefreshTokenRepository{
		RevokeAllForUserFn: func(context.Context, uuid.UUID, string) error { return nil },
	}
	authSvc := auth.NewService(auth.ServiceDeps{
		Redis:           rc,
		Logger:          log,
		Auditor:         audit.NopLogger{},
		Tokens:          tokenSvc.WrapRefreshTokenRepository(pgTokens),
		Issuer:          tokenSvc,
		RefreshTokenTTL: jwtCfg.RefreshTokenTTL,
	})
	sessionSvc = session.NewService(session.NewRedisStore(rc, jwtCfg.RefreshTokenTTL))

	authMW := func(c *gin.Context) {
		c.Set("user_id", c.GetHeader("X-User-ID"))
		c.Next()
	}
	router, err = api.NewPublicRouter(
		&api.Services{Auth: authSvc, Token: tokenSvc, Session: sessionSvc, Logger: log},
		&api.MiddlewareStack{Auth: authMW},
		health.NewService(),
	)
	require.NoError(t, err)
	return tokenSvc, sessionSvc, router
}

func serve(r *gin.Engine, method, path, userID string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, http.NoBody)
	req.Header.Set("X-User-ID", userID)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestTerminateAllSessions_RevokesEarlierRefreshTokens(t *testing.T) {
	ctx := context.Background()
	tokenSvc, sessionSvc, router := newTerminateAllEnv(t)

	// Two logins for the user (two devices) and one for a bystander.
	var refreshTokens []string
	for i := 0; i < 2; i++ {
		pair, err := tokenSvc.IssueTokenPair(ctx, "user-1", nil, nil, domain.ClientTypeUser)
		require.NoError(t, err)
		refreshTokens = append(refreshTokens, pair.RefreshToken)
		_, err = sessionSvc.CreateSession(ctx, "user-1", "203.0.113.7", "TestAgent")
		require.NoError(t, err)
	}
	bystander, err := tokenSvc.IssueTokenPair(ctx, "user-2", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	_, err = sessionSvc.CreateSession(ctx, "user-2", "203.0.113.8", "TestAgent")
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, serve(router, http.MethodGet, "/auth/sessions", "user-1").Code)
	listed, err := sessionSvc.ListSessions(ctx, "user-1")
	require.NoError(t, err)
	require.Len(t, listed, 2)

	w := serve(router, http.MethodDelete, "/auth/sessions", "user-1")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	for i, rt := range refreshTokens {
		_, err := tokenSvc.Refresh(ctx, rt)
		assert.ErrorIs(t, err, api.ErrUnauthorized, "refresh token %d issued before terminate-all must fail", i)
	}

	listed, err = sessionSvc.ListSessions(ctx, "user-1")
	require.NoError(t, err)
	assert.Empty(t, listed)

	_, err = tokenSvc.Refresh(ctx, bystander.RefreshToken)
	assert.NoError(t, err, "other users are unaffected")
	others, err := sessionSvc.ListSessions(ctx, "user-2")
	require.NoError(t, err)
	assert.Len(t, others, 1)
}

func TestTerminateAllSessions_NewLoginAfterwardsWorks(t *testing.T) {
	ctx := context.Background()
	tokenSvc, _, router := newTerminateAllEnv(t)

	require.Equal(t, http.StatusOK, serve(router, http.MethodDelete, "/auth/sessions", "user-1").Code)

	// Revocation is an epoch: tokens issued after it stay valid.
	pair, err := tokenSvc.IssueTokenPair(ctx, "user-1", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	_, err = tokenSvc.Refresh(ctx, pair.RefreshToken)
	assert.NoError(t, err)
}
