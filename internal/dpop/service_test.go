package dpop

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
)

func newTestService(t *testing.T) (*Service, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	cfg := config.DPoPConfig{
		Enabled:   true,
		NonceTTL:  5 * time.Minute,
		JTIWindow: 1 * time.Minute,
	}
	svc := NewService(cfg, rc, zap.NewNop())
	return svc, mr
}

// generateTestECKey creates a P-256 key pair for testing.
func generateTestECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

// buildJWK creates a JWK map from an EC public key.
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

// signDPoPProof creates a signed DPoP proof JWT.
func signDPoPProof(t *testing.T, key *ecdsa.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = buildJWK(&key.PublicKey)

	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// expectedThumbprint computes the expected JWK thumbprint for a key.
func expectedThumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	jwk := buildJWK(pub)
	canonical := map[string]interface{}{
		"crv": jwk["crv"],
		"kty": jwk["kty"],
		"x":   jwk["x"],
		"y":   jwk["y"],
	}
	b, err := json.Marshal(canonical)
	require.NoError(t, err)
	hash := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func TestValidateProof_ValidProof(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "unique-jti-1",
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	result, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")

	require.NoError(t, err)
	assert.Equal(t, expectedThumbprint(t, &key.PublicKey), result.JKTThumbprint)
	assert.Equal(t, "POST", result.HTTPMethod)
	assert.Equal(t, "http://localhost/auth/token", result.HTTPURI)
}

func TestValidateProof_InvalidTyp(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "jti-2",
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Unix()),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "JWT" // Wrong typ
	token.Header["jwk"] = buildJWK(&key.PublicKey)
	signed, err := token.SignedString(key)
	require.NoError(t, err)

	_, err = svc.ValidateProof(context.Background(), signed, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "invalid typ header")
}

func TestValidateProof_HTMMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "jti-3",
		"htm": "GET",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "htm mismatch")
}

func TestValidateProof_HTUMismatch(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "jti-4",
		"htm": "POST",
		"htu": "http://localhost/other",
		"iat": float64(time.Now().Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "htu mismatch")
}

func TestValidateProof_MissingJTI(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "missing jti")
}

func TestValidateProof_ReplayDetection(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "replay-jti",
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Unix()),
	}

	proof := signDPoPProof(t, key, claims)

	// First use should succeed.
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	require.NoError(t, err)

	// Second use with same JTI should fail.
	_, err = svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "replay")
}

func TestValidateProof_ExpiredProof(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "jti-old",
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Add(-10 * time.Minute).Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "too old")
}

func TestValidateProof_FutureIAT(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti": "jti-future",
		"htm": "POST",
		"htu": "http://localhost/auth/token",
		"iat": float64(time.Now().Add(5 * time.Minute).Unix()),
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "future")
}

func TestIssueNonce(t *testing.T) {
	svc, mr := newTestService(t)

	nonce, err := svc.IssueNonce(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, nonce)

	// Verify the nonce exists in Redis.
	key := nonceKeyPrefix + nonce
	val, err := mr.Get(key)
	require.NoError(t, err)
	assert.Equal(t, "1", val)
}

func TestValidateProof_WithValidNonce(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	nonce, err := svc.IssueNonce(context.Background())
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"jti":   "jti-nonce-valid",
		"htm":   "POST",
		"htu":   "http://localhost/auth/token",
		"iat":   float64(time.Now().Unix()),
		"nonce": nonce,
	}

	proof := signDPoPProof(t, key, claims)
	result, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	require.NoError(t, err)
	assert.NotEmpty(t, result.JKTThumbprint)
}

func TestValidateProof_WithInvalidNonce(t *testing.T) {
	svc, _ := newTestService(t)
	key := generateTestECKey(t)

	claims := jwt.MapClaims{
		"jti":   "jti-nonce-invalid",
		"htm":   "POST",
		"htu":   "http://localhost/auth/token",
		"iat":   float64(time.Now().Unix()),
		"nonce": "bogus-nonce",
	}

	proof := signDPoPProof(t, key, claims)
	_, err := svc.ValidateProof(context.Background(), proof, "POST", "http://localhost/auth/token")
	assert.ErrorContains(t, err, "invalid or expired DPoP nonce")
}

func TestEnabled(t *testing.T) {
	mr := miniredis.RunT(t)
	rc := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rc.Close() })

	svc := NewService(config.DPoPConfig{Enabled: false}, rc, zap.NewNop())
	assert.False(t, svc.Enabled())

	svc2 := NewService(config.DPoPConfig{Enabled: true}, rc, zap.NewNop())
	assert.True(t, svc2.Enabled())
}
