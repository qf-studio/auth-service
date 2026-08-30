package token_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	jwtv5 "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
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

// defaultOIDCCfg mirrors config.loadOIDC's defaults (GH-468: OIDC_ISSUER_URL
// default is "https://auth.qf.studio", matching the value this constant used
// to be hardcoded to in service.go before iss became config-driven).
func defaultOIDCCfg() config.OIDCConfig {
	return config.OIDCConfig{
		IssuerURL:  "https://auth.qf.studio",
		IDTokenTTL: 1 * time.Hour,
	}
}

func newES256Service(t *testing.T) (*token.Service, *miniredis.Miniredis) {
	t.Helper()
	key := generateES256Key(t)
	mr, rc := newTestRedis(t)
	cfg := defaultCfg()
	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)
	return svc, mr
}

func newEdDSAService(t *testing.T) (*token.Service, *miniredis.Miniredis) {
	t.Helper()
	key := generateEdDSAKey(t)
	mr, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"
	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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

	svc, err := token.NewService(cfg, defaultOIDCCfg(), rc, testLogger(), audit.NopLogger{})
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

	svc, err := token.NewService(cfg, defaultOIDCCfg(), rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)
	require.NotNil(t, svc)
}

func TestNewService_InvalidKeyPath(t *testing.T) {
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.PrivateKeyPath = "/nonexistent/key.pem"

	_, err := token.NewService(cfg, defaultOIDCCfg(), rc, testLogger(), audit.NopLogger{})
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

	_, err := token.NewService(cfg, defaultOIDCCfg(), rc, testLogger(), audit.NopLogger{})
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

	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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

// TestValidateToken_RejectsIDToken verifies that a cryptographically valid
// OIDC ID token (IssueIDToken) is rejected by ValidateToken with
// domain.ErrNotAccessToken, since ID tokens carry no client_type claim
// (GH-473: gRPC and other ValidateToken callers must not treat an ID token
// as an authenticated access-token subject).
func TestValidateToken_RejectsIDToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	idToken, err := svc.IssueIDToken(ctx, "user-123", "client-abc", "", time.Now())
	require.NoError(t, err)

	_, err = svc.ValidateToken(ctx, idToken)
	require.Error(t, err)
	assert.ErrorIs(t, err, domain.ErrNotAccessToken)
}

// TestValidateToken_AccessTokenOK is a control alongside
// TestValidateToken_RejectsIDToken: a real access token (which always
// carries client_type) must continue to validate successfully.
func TestValidateToken_AccessTokenOK(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"user"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Equal(t, "user-123", claims.Subject)
	assert.Equal(t, domain.ClientTypeUser, claims.ClientType)
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

// ── Audience (GH-449) ────────────────────────────────────────────────────────

func TestIssueAccessToken_Audience(t *testing.T) {
	tests := []struct {
		name     string
		audience []string
		wantAud  []string
	}{
		{name: "configured audience is set on issued token", audience: []string{"https://api.qf.studio"}, wantAud: []string{"https://api.qf.studio"}},
		{name: "multiple audiences are all set", audience: []string{"qf-api", "qf-billing"}, wantAud: []string{"qf-api", "qf-billing"}},
		{name: "unset audience produces no aud claim", audience: nil, wantAud: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateES256Key(t)
			_, rc := newTestRedis(t)
			cfg := defaultCfg()
			cfg.Audience = tt.audience

			svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
			require.NoError(t, err)

			ctx := context.Background()
			result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
			require.NoError(t, err)

			rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")

			// Verify via the parsed domain claims.
			claims, err := svc.ValidateToken(ctx, rawJWT)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAud, claims.Audience)

			// Verify directly against the raw JWT payload so we assert on the
			// wire format, not just the domain mapping.
			parser := jwtv5.NewParser()
			jwtClaims := jwtv5.MapClaims{}
			_, _, err = parser.ParseUnverified(rawJWT, jwtClaims)
			require.NoError(t, err)
			if len(tt.wantAud) == 0 {
				assert.NotContains(t, jwtClaims, "aud")
			} else {
				assert.Contains(t, jwtClaims, "aud")
			}
		})
	}
}

func TestValidateToken_AcceptsAudiencelessTokenWhenAudienceConfigured(t *testing.T) {
	// A token issued before JWT_AUDIENCE was configured (or by another
	// service instance without it set) carries no aud claim. ValidateToken
	// must still accept it: audience validation is deliberately not enforced
	// here to avoid an in-flight rotation hazard (GH-449).
	key := generateES256Key(t)
	_, rc := newTestRedis(t)

	issuerCfg := defaultCfg() // no Audience set
	issuerSvc, err := token.NewServiceFromKey(issuerCfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	result, err := issuerSvc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")

	validatorCfg := defaultCfg()
	validatorCfg.Audience = []string{"https://api.qf.studio"}
	validatorSvc, err := token.NewServiceFromKey(validatorCfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	claims, err := validatorSvc.ValidateToken(ctx, rawJWT)
	require.NoError(t, err)
	assert.Empty(t, claims.Audience)
}

// ── Issuer (GH-468) ──────────────────────────────────────────────────────────

// TestIssueAccessToken_IssuerFromOIDCConfig verifies the `iss` claim on
// issued access tokens tracks config.OIDCConfig.IssuerURL. Before GH-468,
// `iss` was a hardcoded package constant, so overriding OIDC_ISSUER_URL had
// no effect on issued tokens at all; this asserts that override now works.
func TestIssueAccessToken_IssuerFromOIDCConfig(t *testing.T) {
	tests := []struct {
		name      string
		issuerURL string
	}{
		{name: "default issuer", issuerURL: "https://auth.qf.studio"},
		{name: "overridden issuer", issuerURL: "https://issuer.override.example"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := generateES256Key(t)
			_, rc := newTestRedis(t)
			cfg := defaultCfg()
			oidcCfg := config.OIDCConfig{IssuerURL: tt.issuerURL, IDTokenTTL: time.Hour}

			svc, err := token.NewServiceFromKey(cfg, oidcCfg, key, rc, testLogger(), audit.NopLogger{})
			require.NoError(t, err)

			ctx := context.Background()
			result, err := svc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
			require.NoError(t, err)

			rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
			parser := jwtv5.NewParser()
			jwtClaims := jwtv5.MapClaims{}
			_, _, err = parser.ParseUnverified(rawJWT, jwtClaims)
			require.NoError(t, err)

			assert.Equal(t, tt.issuerURL, jwtClaims["iss"])
		})
	}
}

// ── IssueIDToken (GH-468) ────────────────────────────────────────────────────

// idTokenTestClaims mirrors the (unexported) claims shape IssueIDToken
// produces. auth_time and nonce aren't surfaced through domain.TokenClaims
// (that type models access-token claims), so tests decode the raw JWT with
// this local struct instead of reaching into the token package's internals.
type idTokenTestClaims struct {
	jwtv5.RegisteredClaims
	AuthTime int64  `json:"auth_time,omitempty"`
	Nonce    string `json:"nonce,omitempty"`
}

func TestIssueIDToken_ClaimsAndSignature(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	oidcCfg := config.OIDCConfig{IssuerURL: "https://auth.qf.studio", IDTokenTTL: 45 * time.Minute}

	svc, err := token.NewServiceFromKey(cfg, oidcCfg, key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	authTime := time.Now().Add(-90 * time.Second).Truncate(time.Second)
	idToken, err := svc.IssueIDToken(ctx, "user-123", "client-abc", "nonce-xyz", authTime)
	require.NoError(t, err)
	require.NotEmpty(t, idToken)

	// Signature/alg verification: ID tokens carry no client_type claim, so
	// ValidateToken now rejects them (GH-473). Verify the signature directly
	// against the service's own key instead, mirroring
	// internal/oidc/oidc_flow_integration_test.go's idTokenIssuer helper.
	tc := &idTokenTestClaims{}
	parsedToken, err := jwtv5.ParseWithClaims(idToken, tc, func(*jwtv5.Token) (interface{}, error) {
		return &key.PublicKey, nil
	}, jwtv5.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err, "parse/verify ID token")
	assert.Equal(t, "user-123", tc.Subject)
	assert.Equal(t, jwtv5.ClaimStrings{"client-abc"}, tc.Audience)

	assert.Equal(t, "ES256", parsedToken.Method.Alg())

	kid, ok := parsedToken.Header["kid"].(string)
	require.True(t, ok, "id token header must carry a kid")
	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, keyMap["kid"], kid, "id token header kid must match the active JWKS key's kid")

	assert.Equal(t, "https://auth.qf.studio", tc.Issuer)
	assert.Equal(t, "user-123", tc.Subject)
	assert.Equal(t, jwtv5.ClaimStrings{"client-abc"}, tc.Audience)
	assert.Equal(t, "nonce-xyz", tc.Nonce)
	assert.Equal(t, authTime.Unix(), tc.AuthTime)
	require.NotNil(t, tc.IssuedAt)
	require.NotNil(t, tc.ExpiresAt)
	assert.InDelta(t, 45*time.Minute, tc.ExpiresAt.Sub(tc.IssuedAt.Time), float64(2*time.Second),
		"id token TTL must come from OIDCConfig.IDTokenTTL")
}

func TestIssueIDToken_EdDSA(t *testing.T) {
	key := generateEdDSAKey(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"
	oidcCfg := config.OIDCConfig{IssuerURL: "https://auth.qf.studio", IDTokenTTL: time.Hour}

	svc, err := token.NewServiceFromKey(cfg, oidcCfg, key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	idToken, err := svc.IssueIDToken(ctx, "svc-456", "client-def", "", time.Now())
	require.NoError(t, err)

	// ID tokens carry no client_type claim, so ValidateToken rejects them
	// (GH-473); verify the signature directly against the service's key.
	tc := &idTokenTestClaims{}
	parsedToken, err := jwtv5.ParseWithClaims(idToken, tc, func(*jwtv5.Token) (interface{}, error) {
		return key.Public(), nil
	}, jwtv5.WithValidMethods([]string{"EdDSA"}))
	require.NoError(t, err, "parse/verify ID token")
	assert.Equal(t, "svc-456", tc.Subject)
	assert.Equal(t, "EdDSA", parsedToken.Method.Alg())
}

func TestIssueIDToken_NoNonceOmitsClaim(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	idToken, err := svc.IssueIDToken(ctx, "user-123", "client-abc", "", time.Now())
	require.NoError(t, err)

	parser := jwtv5.NewParser()
	jwtClaims := jwtv5.MapClaims{}
	_, _, err = parser.ParseUnverified(idToken, jwtClaims)
	require.NoError(t, err)
	assert.NotContains(t, jwtClaims, "nonce")
}

func TestIssueIDToken_UniqueJTIPerToken(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	first, err := svc.IssueIDToken(ctx, "user-123", "client-abc", "n1", time.Now())
	require.NoError(t, err)
	second, err := svc.IssueIDToken(ctx, "user-123", "client-abc", "n2", time.Now())
	require.NoError(t, err)

	parser := jwtv5.NewParser()
	c1, c2 := &idTokenTestClaims{}, &idTokenTestClaims{}
	_, _, err = parser.ParseUnverified(first, c1)
	require.NoError(t, err)
	_, _, err = parser.ParseUnverified(second, c2)
	require.NoError(t, err)

	assert.NotEmpty(t, c1.ID)
	assert.NotEmpty(t, c2.ID)
	assert.NotEqual(t, c1.ID, c2.ID)
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

	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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

	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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

	oldSvc, err := token.NewServiceFromKey(oldCfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	ctx := context.Background()
	result, err := oldSvc.IssueTokenPair(ctx, "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	// Create new service with rotated secrets (new first, old second).
	newCfg := defaultCfg()
	newCfg.SystemSecrets = []string{"new-secret", "old-secret"}

	newSvc, err := token.NewServiceFromKey(newCfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
	require.NoError(t, err)

	// Old refresh token should still validate with the new service.
	newResult, err := newSvc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, newResult)
}

// ── Refresh Role Enrichment (GH-432) ────────────────────────────────────────

// TestRefresh_EnrichesRolesFromUserLookup simulates the full acceptance flow:
// register (user starts with role "user") -> assign roles via admin API
// (roles become ["user","admin"]) -> login (mints an access token carrying
// the roles at login time) -> refresh (must mint an access token carrying
// the user's *current* roles, not the stale login-time roles). Regression
// test for GH-432: the refresh grant previously dropped the roles claim
// entirely.
func TestRefresh_EnrichesRolesFromUserLookup(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	userID := "usr_gh432"
	currentRoles := []string{"user"} // roles at "registration" time

	userLookup := &mocks.MockUserRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
			require.Equal(t, userID, id)
			return &domain.User{ID: userID, Roles: currentRoles}, nil
		},
	}
	svc.SetUserLookup(userLookup)

	// "login": mints an access token carrying roles as they were at login time.
	loginResult, err := svc.IssueTokenPair(ctx, userID, currentRoles, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	loginClaims, err := svc.ValidateToken(ctx, strings.TrimPrefix(loginResult.AccessToken, "qf_at_"))
	require.NoError(t, err)
	assert.Equal(t, []string{"user"}, loginClaims.Roles)

	// "assign roles via admin API": promote the user to admin after login.
	currentRoles = []string{"user", "admin"}

	// "refresh": must reflect the user's *current* roles, looked up at refresh time.
	refreshResult, err := svc.Refresh(ctx, loginResult.RefreshToken)
	require.NoError(t, err)

	refreshClaims, err := svc.ValidateToken(ctx, strings.TrimPrefix(refreshResult.AccessToken, "qf_at_"))
	require.NoError(t, err)
	require.NotNil(t, refreshClaims)
	assert.Equal(t, []string{"user", "admin"}, refreshClaims.Roles, "refreshed access token must carry the user's current roles")
}

// TestRefresh_NoRolesClaimWhenUserLookupUnset preserves the pre-GH-432
// behavior when no UserLookup is wired (e.g. tests, or services that opt out
// of role enrichment): refresh must still succeed, just without roles.
func TestRefresh_NoRolesClaimWhenUserLookupUnset(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	refreshResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)

	refreshClaims, err := svc.ValidateToken(ctx, strings.TrimPrefix(refreshResult.AccessToken, "qf_at_"))
	require.NoError(t, err)
	assert.Empty(t, refreshClaims.Roles)
}

// TestRefresh_UserLookupErrorFailsOpenWithNoRoles verifies that a transient
// user-lookup failure during refresh doesn't fail the whole refresh (fail-open
// for availability, matching this codebase's convention elsewhere), it just
// results in an access token without the roles claim.
func TestRefresh_UserLookupErrorFailsOpenWithNoRoles(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	userLookup := &mocks.MockUserRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
			return nil, errors.New("db unavailable")
		},
	}
	svc.SetUserLookup(userLookup)

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	refreshResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)

	refreshClaims, err := svc.ValidateToken(ctx, strings.TrimPrefix(refreshResult.AccessToken, "qf_at_"))
	require.NoError(t, err)
	assert.Empty(t, refreshClaims.Roles)
}

// ── Refresh Token Postgres Bookkeeping (GH-486) ─────────────────────────────

// TestRefresh_UpdatesPostgresBookkeeping verifies that rotation revokes the
// old signature's Postgres row and inserts the new signature's row, using
// the configured refresh TTL. Previously refreshInternal was Redis-only, so
// a rotated-away token stayed introspectable as active until its original
// row's TTL expired, and the new token was never introspectable at all.
func TestRefresh_UpdatesPostgresBookkeeping(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	var revokedSig string
	var storedSig, storedUserID string
	var storedExpiry time.Time

	store := &mocks.MockRefreshTokenRepository{
		RevokeFn: func(_ context.Context, _ uuid.UUID, sig string) error {
			revokedSig = sig
			return nil
		},
		StoreFn: func(_ context.Context, _ uuid.UUID, sig, userID string, expiresAt time.Time) error {
			storedSig = sig
			storedUserID = userID
			storedExpiry = expiresAt
			return nil
		},
	}
	svc.SetRefreshTokenStore(store)

	result, err := svc.IssueTokenPair(ctx, "user-486", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	oldSig, ok := domain.RefreshTokenSignature(result.RefreshToken)
	require.True(t, ok)

	refreshResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)

	newSig, ok := domain.RefreshTokenSignature(refreshResult.RefreshToken)
	require.True(t, ok)

	assert.Equal(t, oldSig, revokedSig, "old signature's row should be revoked")
	assert.Equal(t, newSig, storedSig, "new signature's row should be stored")
	assert.Equal(t, "user-486", storedUserID)
	assert.WithinDuration(t, time.Now().Add(defaultCfg().RefreshTokenTTL), storedExpiry, 5*time.Second)
}

// TestRefresh_PostgresFailureDoesNotFailRefresh fault-injects both the
// revoke and store calls to confirm Postgres bookkeeping stays best-effort:
// the refresh grant itself must still succeed since Redis remains the
// authoritative hot-path source.
func TestRefresh_PostgresFailureDoesNotFailRefresh(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	store := &mocks.MockRefreshTokenRepository{
		RevokeFn: func(_ context.Context, _ uuid.UUID, _ string) error {
			return errors.New("db down")
		},
		StoreFn: func(_ context.Context, _ uuid.UUID, _, _ string, _ time.Time) error {
			return errors.New("db down")
		},
	}
	svc.SetRefreshTokenStore(store)

	result, err := svc.IssueTokenPair(ctx, "user-486", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	refreshResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err, "refresh must succeed even when Postgres bookkeeping fails")
	require.NotNil(t, refreshResult)
}

// TestRefresh_NoPostgresStoreConfiguredStillWorks preserves refresh behavior
// when SetRefreshTokenStore is never called (e.g. most existing tests in
// this file): rotation stays Redis-only, same as before GH-486.
func TestRefresh_NoPostgresStoreConfiguredStillWorks(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-486", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	refreshResult, err := svc.Refresh(ctx, result.RefreshToken)
	require.NoError(t, err)
	require.NotNil(t, refreshResult)
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

// ── kid: JWKS + token header agreement ───────────────────────────────────────

func TestJWKS_ES256_HasStableKID(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	jwks1, err := svc.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks1.Keys, 1)
	keyMap1, ok := jwks1.Keys[0].(map[string]interface{})
	require.True(t, ok)

	kid1, ok := keyMap1["kid"].(string)
	require.True(t, ok, "JWKS entry must carry a kid")
	assert.NotEmpty(t, kid1)

	// Calling JWKS again must yield the same kid (deterministic, survives
	// "restarts" in the sense of repeated derivation from the same key).
	jwks2, err := svc.JWKS(ctx)
	require.NoError(t, err)
	keyMap2, ok := jwks2.Keys[0].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, kid1, keyMap2["kid"])
}

func TestJWKS_EdDSA_HasStableKID(t *testing.T) {
	svc, _ := newEdDSAService(t)
	ctx := context.Background()

	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)

	kid, ok := keyMap["kid"].(string)
	require.True(t, ok, "JWKS entry must carry a kid")
	assert.NotEmpty(t, kid)
}

func TestIssueAccessToken_HeaderKIDMatchesJWKS_ES256(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "user-123", []string{"admin"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	parser := jwtv5.NewParser()
	parsed, _, err := parser.ParseUnverified(rawJWT, jwtv5.MapClaims{})
	require.NoError(t, err)

	headerKID, ok := parsed.Header["kid"].(string)
	require.True(t, ok, "access token header must carry a kid")
	assert.NotEmpty(t, headerKID)

	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)
	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, keyMap["kid"], headerKID, "token header kid must match the active JWKS key's kid")
}

func TestIssueAccessToken_HeaderKIDMatchesJWKS_EdDSA(t *testing.T) {
	svc, _ := newEdDSAService(t)
	ctx := context.Background()

	result, err := svc.IssueTokenPair(ctx, "svc-456", []string{"service"}, nil, domain.ClientTypeService)
	require.NoError(t, err)

	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	parser := jwtv5.NewParser()
	parsed, _, err := parser.ParseUnverified(rawJWT, jwtv5.MapClaims{})
	require.NoError(t, err)

	headerKID, ok := parsed.Header["kid"].(string)
	require.True(t, ok, "access token header must carry a kid")
	assert.NotEmpty(t, headerKID)

	jwks, err := svc.JWKS(ctx)
	require.NoError(t, err)
	keyMap, ok := jwks.Keys[0].(map[string]interface{})
	require.True(t, ok)

	assert.Equal(t, keyMap["kid"], headerKID, "token header kid must match the active JWKS key's kid")
}

func TestJWKS_DifferentKeysHaveDifferentKID(t *testing.T) {
	svc1, _ := newES256Service(t)
	svc2, _ := newES256Service(t)
	ctx := context.Background()

	jwks1, err := svc1.JWKS(ctx)
	require.NoError(t, err)
	jwks2, err := svc2.JWKS(ctx)
	require.NoError(t, err)

	keyMap1 := jwks1.Keys[0].(map[string]interface{})
	keyMap2 := jwks2.Keys[0].(map[string]interface{})

	assert.NotEqual(t, keyMap1["kid"], keyMap2["kid"], "distinct keys must produce distinct kids")
}

// ── ClientCredentials (stub) ─────────────────────────────────────────────────

func TestClientCredentials_ReturnsNotImplemented(t *testing.T) {
	svc, _ := newES256Service(t)
	ctx := context.Background()

	_, err := svc.ClientCredentials(ctx, "client-id", "client-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

// ── NewServiceFromKey validation ─────────────────────────────────────────────

func TestNewServiceFromKey_AlgorithmMismatch(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.Algorithm = "EdDSA"

	_, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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

	svc, err := token.NewService(cfg, defaultOIDCCfg(), rc, testLogger(), audit.NopLogger{})
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

// ── Benchmarks ───────────────────────────────────────────────────────────────

func newBenchES256Service(b *testing.B) *token.Service {
	b.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	mr := miniredis.RunT(b)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	b.Cleanup(func() { _ = rc.Close() })
	cfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"bench-secret"},
	}
	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, zap.NewNop(), audit.NopLogger{})
	if err != nil {
		b.Fatal(err)
	}
	return svc
}

func BenchmarkIssueTokenPair(b *testing.B) {
	svc := newBenchES256Service(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.IssueTokenPair(ctx, "bench-user", []string{"user"}, []string{"read:all"}, domain.ClientTypeUser)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateToken(b *testing.B) {
	svc := newBenchES256Service(b)
	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "bench-user", []string{"user"}, []string{"read:all"}, domain.ClientTypeUser)
	if err != nil {
		b.Fatal(err)
	}
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.ValidateToken(ctx, rawJWT)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRefresh(b *testing.B) {
	// Each iteration needs a fresh refresh token since Refresh() rotates tokens.
	// We pre-issue b.N token pairs before the timer starts.
	svc := newBenchES256Service(b)
	ctx := context.Background()

	tokens := make([]string, b.N)
	for i := 0; i < b.N; i++ {
		result, err := svc.IssueTokenPair(ctx, "bench-user", []string{"user"}, nil, domain.ClientTypeUser)
		if err != nil {
			b.Fatal(err)
		}
		tokens[i] = result.RefreshToken
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.Refresh(ctx, tokens[i])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIsRevoked_NotRevoked(b *testing.B) {
	svc := newBenchES256Service(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.IsRevoked(ctx, "nonexistent-jti-bench")
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIsRevoked_Revoked(b *testing.B) {
	svc := newBenchES256Service(b)
	ctx := context.Background()
	result, err := svc.IssueTokenPair(ctx, "bench-user", nil, nil, domain.ClientTypeUser)
	if err != nil {
		b.Fatal(err)
	}
	rawJWT := strings.TrimPrefix(result.AccessToken, "qf_at_")
	claims, err := svc.ValidateToken(ctx, rawJWT)
	if err != nil {
		b.Fatal(err)
	}
	if err := svc.Revoke(ctx, result.AccessToken); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.IsRevoked(ctx, claims.TokenID)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkJWKS(b *testing.B) {
	svc := newBenchES256Service(b)
	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := svc.JWKS(ctx)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// ── IssueTokenPair with no system secrets ────────────────────────────────────

func TestIssueTokenPair_NoSystemSecretsError(t *testing.T) {
	key := generateES256Key(t)
	_, rc := newTestRedis(t)
	cfg := defaultCfg()
	cfg.SystemSecrets = nil

	svc, err := token.NewServiceFromKey(cfg, defaultOIDCCfg(), key, rc, testLogger(), audit.NopLogger{})
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
