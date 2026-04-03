package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/token"
)

// ── Test helpers ─────────────────────────────────────────────────────────────

func generateES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func generateEdDSAKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	return priv
}

func writeKeyToFile(t *testing.T, dir string, key interface{}) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	path := filepath.Join(dir, "private.pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()

	err = pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der})
	require.NoError(t, err)
	return path
}

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func testLogger() *zap.Logger {
	return zap.NewNop()
}

func defaultCfg() config.JWTConfig {
	return config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret-1"},
	}
}

func newES256Service(t *testing.T) (*token.Service, *miniredis.Miniredis) {
	t.Helper()
	key := generateES256Key(t)
	mr, rc := newTestRedis(t)
	cfg := defaultCfg()
	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)
	return svc, mr
}

func newEdDSAService(t *testing.T) (*token.Service, *miniredis.Miniredis) {
	t.Helper()
	key := generateEdDSAKey(t)
	mr, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"
	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)
	return svc, mr
}

// ── NewService (from file) ───────────────────────────────────────────────────

func TestNewService_ES256FromFile(t *testing.T) {
	key := generateES256Key(t)
	dir := t.TempDir()
	keyPath := writeKeyToFile(t, dir, key)

	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.PrivateKeyPath = keyPath

	svc, err := token.NewService(cfg, rc, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewService_EdDSAFromFile(t *testing.T) {
	key := generateEdDSAKey(t)
	dir := t.TempDir()
	keyPath := writeKeyToFile(t, dir, key)

	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"
	cfg.PrivateKeyPath = keyPath

	svc, err := token.NewService(cfg, rc, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewService_InvalidKeyPath(t *testing.T) {
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.PrivateKeyPath = "/nonexistent/key.pem"

	_, err := token.NewService(cfg, rc, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "read private key")
}

func TestNewService_AlgorithmMismatch(t *testing.T) {
	key := generateES256Key(t)
	dir := t.TempDir()
	keyPath := writeKeyToFile(t, dir, key)

	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.PrivateKeyPath = keyPath
	cfg.Algorithm = "EdDSA" // ECDSA key with EdDSA algorithm

	_, err := token.NewService(cfg, rc, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse private key")
}

// ── IssueTokenPair ───────────────────────────────────────────────────────────

func TestIssueTokenPair_ES256(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin"}, []string{"read:users"}, domain.ClientTypeUser)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, strings.HasPrefix(result.AccessToken, "qf_at_"), "access token must have qf_at_ prefix")
	assert.True(t, strings.HasPrefix(result.RefreshToken, "qf_rt_"), "refresh token must have qf_rt_ prefix")
	assert.Equal(t, "Bearer", result.TokenType)
	assert.Equal(t, 900, result.ExpiresIn) // 15 minutes
}

func TestIssueTokenPair_EdDSA(t *testing.T) {
	svc, _ := newEdDSAService(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "svc-456", []string{"service"}, []string{"write:tokens"}, domain.ClientTypeService)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.True(t, strings.HasPrefix(result.AccessToken, "qf_at_"))
	assert.True(t, strings.HasPrefix(result.RefreshToken, "qf_rt_"))
	assert.Equal(t, "Bearer", result.TokenType)
}

func TestIssueTokenPair_NilRolesScopes(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "agent-789", nil, nil, domain.ClientTypeAgent)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Validate the access token can be parsed.
	claims, err := svc.ValidateToken(ctx, strings.TrimPrefix(result.AccessToken, "qf_at_"))
	require.NoError(t, err)
	assert.Equal(t, "agent-789", claims.Subject)
	assert.Equal(t, domain.ClientTypeAgent, claims.ClientType)
}

// ── ValidateToken ────────────────────────────────────────────────────────────

func TestValidateToken_Success(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin", "user"}, []string{"read:users", "write:users"}, domain.ClientTypeUser)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	require.NotNil(t, claims)

	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, []string{"admin", "user"}, claims.Roles)
	assert.Equal(t, []string{"read:users", "write:users"}, claims.Scopes)
	assert.Equal(t, domain.ClientTypeUser, claims.ClientType)
	assert.NotEmpty(t, claims.TokenID)
}

func TestValidateToken_EdDSA(t *testing.T) {
	svc, _ := newEdDSAService(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "svc-100", []string{"service"}, nil, domain.ClientTypeService)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, "svc-100", claims.Subject)
	assert.Equal(t, domain.ClientTypeService, claims.ClientType)
}

func TestValidateToken_InvalidSignature(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")

	// Replace the entire signature segment with a different base64url string.
	parts := strings.SplitN(rawJWT, ".", 3)
	require.Len(t, parts, 3)
	corrupted := parts[0] + "." + parts[1] + "." + "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	_, err = svc.ValidateToken(ctx, corrupted)
	require.Error(t, err)
}

func TestValidateToken_ExpiredToken(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.AccessTokenTTL = 1 * time.Millisecond // Very short TTL

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Wait for expiry.
	time.Sleep(10 * time.Millisecond)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	_, err = svc.ValidateToken(ctx, rawJWT)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exp")
}

func TestValidateToken_GarbageInput(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	_, err := svc.ValidateToken(ctx, "not-a-jwt")
	require.Error(t, err)
}

func TestValidateToken_WrongSigningKey(t *testing.T) {
	svc1, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc1.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Create a second service with a different key.
	svc2, _ := newES256Service(t)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	_, err = svc2.ValidateToken(ctx, rawJWT)
	require.Error(t, err)
}

// ── Revoke & IsRevoked ───────────────────────────────────────────────────────

func TestRevoke_AccessToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Validate works before revocation.
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)

	// Not revoked yet.
	revoked, err := svc.IsRevoked(ctx, claims.TokenID)
	require.NoError(t, err)
	assert.False(t, revoked)

	// Revoke.
	err = svc.Revoke(ctx, result.AccessToken)
	require.NoError(t, err)

	// Now it's revoked.
	revoked, err = svc.IsRevoked(ctx, claims.TokenID)
	require.NoError(t, err)
	assert.True(t, revoked)
}

func TestRevoke_GarbageTokenDoesNotError(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	// RFC 7009: revocation endpoint should succeed even for invalid tokens.
	err := svc.Revoke(ctx, "garbage-token")
	require.NoError(t, err)
}

func TestIsRevoked_NonexistentTokenID(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	revoked, err := svc.IsRevoked(ctx, "nonexistent-jti")
	require.NoError(t, err)
	assert.False(t, revoked)
}

func TestRevoke_ExpiredTokenNoBlocklist(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.AccessTokenTTL = 1 * time.Millisecond

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	time.Sleep(10 * time.Millisecond)

	// Revoking an expired token should not add to blocklist (already expired).
	err = svc.Revoke(ctx, result.AccessToken)
	require.NoError(t, err)
}

// ── Refresh Token ────────────────────────────────────────────────────────────

func TestRefresh_Success(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	// Issue initial pair.
	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Refresh using the refresh token.
	newResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, newResult)

	assert.True(t, strings.HasPrefix(newResult.AccessToken, "qf_at_"))
	assert.True(t, strings.HasPrefix(newResult.RefreshToken, "qf_rt_"))
	assert.Equal(t, "Bearer", newResult.TokenType)

	// Old refresh token should be rotated (deleted).
	_, err = svc.Refresh(ctx, result.RefreshToken)
	require.Error(t, err, "old refresh token should be invalidated after rotation")
}

func TestRefresh_InvalidToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	_, err := svc.Refresh(ctx, "qf_rt_invalid.signature")
	require.Error(t, err)
}

func TestRefresh_MalformedToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	_, err := svc.Refresh(ctx, "not-a-refresh-token")
	require.Error(t, err)
}

func TestRefresh_ExpiredRefreshToken(t *testing.T) {
	key := generateES256Key(t)
	mr, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.RefreshTokenTTL = 1 * time.Second

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Fast-forward miniredis time to expire the refresh token.
	mr.FastForward(2 * time.Second)

	_, err = svc.Refresh(ctx, result.RefreshToken)
	require.Error(t, err)
}

// ── Refresh Token Secret Rotation ────────────────────────────────────────────

func TestRefresh_SecretRotation(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)

	// Issue with old secret.
	oldCfg := defaultCfg()
	oldCfg.SystemSecrets = []string{"old-secret"}

	oldSvc, err := token.NewServiceFromKey(oldCfg, key, rc, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	result, err := oldSvc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Create new service with rotated secrets (new first, old second).
	newCfg := defaultCfg()
	newCfg.SystemSecrets = []string{"new-secret", "old-secret"}

	newSvc, err := token.NewServiceFromKey(newCfg, key, rc, testLogger())
	require.NoError(t, err)

	// Old refresh token should still validate with the new service.
	newResult, err := newSvc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, newResult)
}

// ── JWKS ─────────────────────────────────────────────────────────────────────

func TestJWKS_ES256(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "EC", keyMap["kty"])
	assert.Equal(t, "P-256", keyMap["crv"])
	assert.Equal(t, "ES256", keyMap["alg"])
	assert.Equal(t, "sig", keyMap["use"])
	assert.NotEmpty(t, keyMap["x"])
	assert.NotEmpty(t, keyMap["y"])
}

func TestJWKS_EdDSA(t *testing.T) {
	svc, _ := newEdDSAService(t)
	ctx := context.Background()

	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, "OKP", keyMap["kty"])
	assert.Equal(t, "Ed25519", keyMap["crv"])
	assert.Equal(t, "EdDSA", keyMap["alg"])
	assert.Equal(t, "sig", keyMap["use"])
	assert.NotEmpty(t, keyMap["x"])
}

// ── ClientCredentials ─────────────────────────────────────────────────────────

func TestClientCredentials_NoAuthenticator(t *testing.T) {
	svc, _ := newES256Service(t)

	_, err := svc.ClientCredentials(context.Background(), "client-id", "client-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client authenticator not configured")
}

// ── NewServiceFromKey validation ─────────────────────────────────────────────

func TestNewServiceFromKey_AlgorithmMismatch(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"

	_, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ECDSA")
}

// ── EC key file parsing ──────────────────────────────────────────────────────

func TestNewService_ECKeyFile(t *testing.T) {
	key := generateES256Key(t)
	dir := t.TempDir()

	// Write as EC PRIVATE KEY (SEC 1) format instead of PKCS8.
	der, err := x509.MarshalECPrivateKey(key)
	require.NoError(t, err)

	path := filepath.Join(dir, "ec.pem")
	f, err := os.Create(path)
	require.NoError(t, err)
	err = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
	require.NoError(t, err)
	_ = f.Close()

	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.PrivateKeyPath = path

	svc, err := token.NewService(cfg, rc, testLogger())
	require.NoError(t, err)
	require.NotNil(t, svc)
}

// ── End-to-end: issue, validate, revoke, check ───────────────────────────────

func TestEndToEnd_IssueValidateRevokeCheck(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	// 1. Issue token pair.
	result, err := svc.IssueTokenPair(ctx, "user-e2e", []string{"user"}, []string{"read:all"}, domain.ClientTypeUser)
	require.NoError(t, err)

	// 2. Validate access token.
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, "user-e2e", claims.Subject)

	// 3. Not revoked.
	revoked, err := svc.IsRevoked(ctx, claims.TokenID)
	require.NoError(t, err)
	assert.False(t, revoked)

	// 4. Revoke.
	err = svc.Revoke(ctx, result.AccessToken)
	require.NoError(t, err)

	// 5. Now revoked.
	revoked, err = svc.IsRevoked(ctx, claims.TokenID)
	require.NoError(t, err)
	assert.True(t, revoked)

	// 6. Refresh token still works independently (revocation is for access tokens).
	newResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, newResult)

	// 7. Validate new access token.
	newRawJWT := strings.TrimPrefix(newResult.AccessToken, "qf_at_")
	newClaims, err := svc.ValidateToken(ctx, newRawJWT)
	require.NoError(t, err)
	assert.Equal(t, "user-e2e", newClaims.Subject)
	// New token has different JTI.
	assert.NotEqual(t, claims.TokenID, newClaims.TokenID)
}

// ── IssueTokenPair with no system secrets ────────────────────────────────────

func TestIssueTokenPair_NoSystemSecretsError(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.SystemSecrets = nil

	svc, err := token.NewServiceFromKey(cfg, key, rc, testLogger())
	require.NoError(t, err)

	ctx := context.Background()
	_, err = svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no system secrets")
}

// ── Unique JTI per token ─────────────────────────────────────────────────────

func TestIssueTokenPair_UniqueJTI(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	jtis := make(map[string]bool)
	for i := 0; i < 10; i++ {
		result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
		require.NoError(t, err)

		rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
		claims, err := svc.ValidateToken(ctx, rawJWT)
		require.NoError(t, err)

		assert.False(t, jtis[claims.TokenID], "JTI %s was not unique", claims.TokenID)
		jtis[claims.TokenID] = true
	}
}
