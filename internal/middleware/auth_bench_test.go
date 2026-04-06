package middleware_test

// Benchmarks for the full token-validation middleware chain:
//   extract Bearer token → validate JWT (ES256/EdDSA) → check Redis revocation
//
// Target: p99 < 50 ms under load (measured here as mean; real p99 requires
// a load-test harness — these benchmarks expose per-operation baselines).
//
// Run:
//   go test -bench=BenchmarkAuthMiddleware -benchmem ./internal/middleware/
//   go test -bench=BenchmarkAuthMiddleware -benchtime=5s -benchmem ./internal/middleware/

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	ginmode "github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/token"
)

// ── Helpers ───────────────────────────────────────────────────────────────────

func benchNewES256Service(b *testing.B) (*token.Service, *miniredis.Miniredis) {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)

	mr := miniredis.RunT(b)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b.Cleanup(func() { _ = rc.Close() })

	cfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"bench-secret"},
	}
	svc, err := token.NewServiceFromKey(cfg, key, rc, zap.NewNop(), audit.NopLogger{})
	require.NoError(b, err)
	return svc, mr
}

func benchNewEdDSAService(b *testing.B) (*token.Service, *miniredis.Miniredis) {
	b.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(b, err)

	mr := miniredis.RunT(b)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b.Cleanup(func() { _ = rc.Close() })

	cfg := config.JWTConfig{
		Algorithm:       "EdDSA",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"bench-secret"},
	}
	svc, err := token.NewServiceFromKey(cfg, priv, rc, zap.NewNop(), audit.NopLogger{})
	require.NoError(b, err)
	return svc, mr
}

// issueToken issues a real access token via the service and returns the raw
// Bearer value (including the qf_at_ prefix).
func issueToken(b *testing.B, svc *token.Service) string {
	b.Helper()
	result, err := svc.IssueTokenPair(
		context.Background(),
		"bench-user",
		[]string{"user"},
		[]string{"read:self"},
		"user",
	)
	require.NoError(b, err)
	return result.AccessToken // already has qf_at_ prefix
}

// newBenchRouter builds a Gin router (release mode) with AuthMiddleware wired.
func newBenchRouter(svc middleware.TokenValidator) *gin.Engine {
	ginmode.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(middleware.AuthMiddleware(svc))
	r.GET("/protected", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

// ── Benchmarks ────────────────────────────────────────────────────────────────

// BenchmarkAuthMiddlewareChain_ES256 measures the full middleware chain with
// ES256-signed tokens: extract Bearer → parse+verify JWT → Redis EXISTS check.
func BenchmarkAuthMiddlewareChain_ES256(b *testing.B) {
	svc, _ := benchNewES256Service(b)
	bearerToken := issueToken(b, svc)

	router := newBenchRouter(svc)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkAuthMiddlewareChain_EdDSA measures the same chain with EdDSA tokens.
func BenchmarkAuthMiddlewareChain_EdDSA(b *testing.B) {
	svc, _ := benchNewEdDSAService(b)
	bearerToken := issueToken(b, svc)

	router := newBenchRouter(svc)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			b.Fatalf("unexpected status %d", w.Code)
		}
	}
}

// BenchmarkAuthMiddlewareChain_Revoked measures the chain when IsRevoked
// returns true (token is in the blocklist). This exercises the Redis hot path
// where the EXISTS key is found.
func BenchmarkAuthMiddlewareChain_Revoked(b *testing.B) {
	svc, _ := benchNewES256Service(b)
	bearerToken := issueToken(b, svc)

	// Revoke the token so subsequent requests hit the revoked branch.
	err := svc.Revoke(context.Background(), bearerToken)
	require.NoError(b, err)

	router := newBenchRouter(svc)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+bearerToken)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			b.Fatalf("expected 401 for revoked token, got %d", w.Code)
		}
	}
}

// BenchmarkAuthMiddlewareChain_MissingHeader measures the fast-path rejection
// when Authorization header is absent (no crypto, no Redis).
func BenchmarkAuthMiddlewareChain_MissingHeader(b *testing.B) {
	svc, _ := benchNewES256Service(b)
	router := newBenchRouter(svc)

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			b.Fatalf("expected 401 for missing header, got %d", w.Code)
		}
	}
}

// BenchmarkAuthMiddlewareChain_InvalidToken measures the chain when the JWT
// signature fails (crypto hot path with early exit before Redis).
func BenchmarkAuthMiddlewareChain_InvalidToken(b *testing.B) {
	svc, _ := benchNewES256Service(b)
	router := newBenchRouter(svc)

	// A well-formed qf_at_ prefixed but tampered JWT.
	// Use a real token from another key so the parse+verify path executes fully.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(b, err)
	otherCfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"other-secret"},
	}
	mr2 := miniredis.RunT(b)
	rc2 := redis.NewClient(&redis.Options{Addr: mr2.Addr()})
	b.Cleanup(func() { _ = rc2.Close() })
	otherSvc, err := token.NewServiceFromKey(otherCfg, otherKey, rc2, zap.NewNop(), audit.NopLogger{})
	require.NoError(b, err)
	wrongToken := issueToken(b, otherSvc) // signed with different key

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
		req.Header.Set("Authorization", "Bearer "+wrongToken)
		router.ServeHTTP(w, req)
		if w.Code != http.StatusUnauthorized {
			b.Fatalf("expected 401 for invalid token, got %d", w.Code)
		}
	}
}
