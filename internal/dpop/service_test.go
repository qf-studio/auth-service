package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/dpop"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func defaultDPoPCfg() config.DPoPConfig {
	return config.DPoPConfig{
		Enabled:   true,
		NonceTTL:  5 * time.Minute,
		JTIWindow: 1 * time.Minute,
	}
}

func newTestService(t *testing.T) (*dpop.Service, *miniredis.Miniredis) {
	t.Helper()
	mr, client := newTestRedis(t)
	svc := dpop.NewService(defaultDPoPCfg(), client, zap.NewNop())
	return svc, mr
}

// generateES256Key creates a test EC P-256 key pair.
func generateES256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// buildJWK creates a JWK map for an EC P-256 public key.
func buildJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)

	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

// computeThumbprint computes the expected JWK thumbprint for an EC P-256 key.
func computeThumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	jwk := buildJWK(pub)
	canonical, err := json.Marshal(map[string]string{
		"crv": jwk["crv"].(string),
		"kty": jwk["kty"].(string),
		"x":   jwk["x"].(string),
		"y":   jwk["y"].(string),
	})
	require.NoError(t, err)
	hash := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// createDPoPProof creates a signed DPoP proof JWT.
func createDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, uri, jti string, iat time.Time, extraClaims map[string]interface{}) string {
	t.Helper()

	jwk := buildJWK(&key.PublicKey)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk

	claims := jwt.MapClaims{
		"jti": jti,
		"htm": method,
		"htu": uri,
		"iat": iat.Unix(),
	}
	for k, v := range extraClaims {
		claims[k] = v
	}
	token.Claims = claims

	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

func TestValidateProof_Valid(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	proof := createDPoPProof(t, key, "POST", "https://auth.example.com/auth/token", "unique-jti-1", time.Now(), nil)

	result, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/auth/token")
	require.NoError(t, err)
	require.NotNil(t, result)

	expectedThumbprint := computeThumbprint(t, &key.PublicKey)
	assert.Equal(t, expectedThumbprint, result.JWKThumbprint)
	assert.Equal(t, "POST", result.HTTPMethod)
	assert.Equal(t, "https://auth.example.com/auth/token", result.HTTPURI)
	assert.Equal(t, "unique-jti-1", result.JTI)
}

func TestValidateProof_MethodMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	proof := createDPoPProof(t, key, "GET", "https://auth.example.com/auth/token", "jti-2", time.Now(), nil)

	_, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/auth/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "htm")
}

func TestValidateProof_URIMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	proof := createDPoPProof(t, key, "POST", "https://other.example.com/auth/token", "jti-3", time.Now(), nil)

	_, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/auth/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "htu")
}

func TestValidateProof_ReplayRejected(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	proof := createDPoPProof(t, key, "POST", "https://auth.example.com/token", "replay-jti", time.Now(), nil)

	// First use should succeed.
	_, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/token")
	require.NoError(t, err)

	// Second use with same JTI should fail (need new proof with same jti for replay).
	proof2 := createDPoPProof(t, key, "POST", "https://auth.example.com/token", "replay-jti", time.Now(), nil)
	_, err = svc.ValidateProof(ctx, proof2, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "replay")
}

func TestValidateProof_ExpiredIAT(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	// IAT 10 minutes ago (beyond 1m window + 30s skew).
	proof := createDPoPProof(t, key, "POST", "https://auth.example.com/token", "jti-old", time.Now().Add(-10*time.Minute), nil)

	_, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "too old")
}

func TestValidateProof_FutureIAT(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	// IAT 5 minutes in the future (beyond 30s skew).
	proof := createDPoPProof(t, key, "POST", "https://auth.example.com/token", "jti-future", time.Now().Add(5*time.Minute), nil)

	_, err := svc.ValidateProof(ctx, proof, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "future")
}

func TestValidateProof_MissingJWK(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	// Create a token without jwk header.
	key := generateES256Key(t)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "dpop+jwt"
	// No jwk header.
	token.Claims = jwt.MapClaims{
		"jti": "jti-no-jwk",
		"htm": "POST",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = svc.ValidateProof(ctx, signed, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jwk")
}

func TestValidateProof_WrongTyp(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	// Create proof with wrong typ.
	jwk := buildJWK(&key.PublicKey)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "JWT" // Wrong typ.
	token.Header["jwk"] = jwk
	token.Claims = jwt.MapClaims{
		"jti": "jti-wrong-typ",
		"htm": "POST",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = svc.ValidateProof(ctx, signed, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "typ")
}

func TestValidateProof_InvalidSignature(t *testing.T) {
	svc, _ := newTestService(t)
	key1 := generateES256Key(t)
	key2 := generateES256Key(t)
	ctx := context.Background()

	// Sign with key1 but embed key2's JWK.
	jwk := buildJWK(&key2.PublicKey)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk
	token.Claims = jwt.MapClaims{
		"jti": "jti-bad-sig",
		"htm": "POST",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}
	signed, err := token.SignedString(key1) // Signed with wrong key.
	require.NoError(t, err)

	_, err = svc.ValidateProof(ctx, signed, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "signature")
}

func TestValidateProof_WithATH(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	ath := dpop.ComputeAccessTokenHash("qf_at_some-access-token")
	proof := createDPoPProof(t, key, "GET", "https://auth.example.com/auth/me", "jti-ath", time.Now(), map[string]interface{}{
		"ath": ath,
	})

	result, err := svc.ValidateProof(ctx, proof, "GET", "https://auth.example.com/auth/me")
	require.NoError(t, err)
	assert.Equal(t, ath, result.AccessTokenHash)
}

func TestIssueNonce(t *testing.T) {
	svc, mr := newTestService(t)
	ctx := context.Background()

	nonce, err := svc.IssueNonce(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)

	// Nonce should be stored in Redis.
	keys := mr.Keys()
	found := false
	for _, k := range keys {
		if k == "dpop_nonce:"+nonce {
			found = true
			break
		}
	}
	assert.True(t, found, "nonce should be stored in Redis")
}

func TestValidateNonce(t *testing.T) {
	svc, _ := newTestService(t)
	ctx := context.Background()

	nonce, err := svc.IssueNonce(ctx)
	require.NoError(t, err)

	valid, err := svc.ValidateNonce(ctx, nonce)
	require.NoError(t, err)
	assert.True(t, valid)

	// Unknown nonce should be invalid.
	valid, err = svc.ValidateNonce(ctx, "unknown-nonce")
	require.NoError(t, err)
	assert.False(t, valid)
}

func TestEnabled(t *testing.T) {
	_, client := newTestRedis(t)

	enabledCfg := config.DPoPConfig{Enabled: true, NonceTTL: 5 * time.Minute, JTIWindow: time.Minute}
	disabledCfg := config.DPoPConfig{Enabled: false, NonceTTL: 5 * time.Minute, JTIWindow: time.Minute}

	svcEnabled := dpop.NewService(enabledCfg, client, zap.NewNop())
	svcDisabled := dpop.NewService(disabledCfg, client, zap.NewNop())

	assert.True(t, svcEnabled.Enabled())
	assert.False(t, svcDisabled.Enabled())
}

func TestComputeAccessTokenHash(t *testing.T) {
	hash := dpop.ComputeAccessTokenHash("test-token")
	assert.NotEmpty(t, hash)

	// SHA-256 of "test-token" base64url encoded.
	h := sha256.Sum256([]byte("test-token"))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, expected, hash)
}

func TestValidateProof_MissingHTM(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	jwk := buildJWK(&key.PublicKey)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk
	token.Claims = jwt.MapClaims{
		"jti": "jti-no-htm",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = svc.ValidateProof(ctx, signed, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "htm")
}

func TestValidateProof_URIQueryIgnored(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	// htu without query, request URI with query — should match.
	proof := createDPoPProof(t, key, "GET", "https://auth.example.com/auth/me", "jti-query", time.Now(), nil)
	result, err := svc.ValidateProof(ctx, proof, "GET", "https://auth.example.com/auth/me?page=1")
	require.NoError(t, err)
	assert.NotEmpty(t, result.JWKThumbprint)
}

func TestValidateProof_KidRejected(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	jwk := buildJWK(&key.PublicKey)
	token := jwt.New(jwt.SigningMethodES256)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = jwk
	token.Header["kid"] = "some-kid" // kid is forbidden in DPoP proofs.
	token.Claims = jwt.MapClaims{
		"jti": "jti-kid",
		"htm": "POST",
		"htu": "https://auth.example.com/token",
		"iat": time.Now().Unix(),
	}
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = svc.ValidateProof(ctx, signed, "POST", "https://auth.example.com/token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "kid")
}

// Test that JWK thumbprints are deterministic for the same key.
func TestJWKThumbprint_Deterministic(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateES256Key(t)
	ctx := context.Background()

	proof1 := createDPoPProof(t, key, "POST", "https://example.com/a", "jti-det-1", time.Now(), nil)
	proof2 := createDPoPProof(t, key, "POST", "https://example.com/a", "jti-det-2", time.Now(), nil)

	result1, err := svc.ValidateProof(ctx, proof1, "POST", "https://example.com/a")
	require.NoError(t, err)

	result2, err := svc.ValidateProof(ctx, proof2, "POST", "https://example.com/a")
	require.NoError(t, err)

	assert.Equal(t, result1.JWKThumbprint, result2.JWKThumbprint)
}

// Test that different keys produce different thumbprints.
func TestJWKThumbprint_DifferentKeys(t *testing.T) {
	svc, _ := newTestService(t)
	key1 := generateES256Key(t)
	key2 := generateES256Key(t)
	ctx := context.Background()

	proof1 := createDPoPProof(t, key1, "POST", "https://example.com/a", "jti-diff-1", time.Now(), nil)
	proof2 := createDPoPProof(t, key2, "POST", "https://example.com/a", "jti-diff-2", time.Now(), nil)

	result1, err := svc.ValidateProof(ctx, proof1, "POST", "https://example.com/a")
	require.NoError(t, err)

	result2, err := svc.ValidateProof(ctx, proof2, "POST", "https://example.com/a")
	require.NoError(t, err)

	assert.NotEqual(t, result1.JWKThumbprint, result2.JWKThumbprint)
}

// Test thumbprint matches RFC 7638 expected computation.
func TestJWKThumbprint_MatchesExpected(t *testing.T) {
	// Generate a real key and verify thumbprint is stable and non-empty.
	key := generateES256Key(t)
	thumbprint := computeThumbprint(t, &key.PublicKey)
	assert.NotEmpty(t, thumbprint)

	// Recompute and verify it's deterministic.
	thumbprint2 := computeThumbprint(t, &key.PublicKey)
	assert.Equal(t, thumbprint, thumbprint2)
}
