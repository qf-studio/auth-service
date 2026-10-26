package dpop_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/dpop"
)

// ── Test helpers ────────────────────────────────────────────────────────────

const (
	testMethod = "POST"
	testURL    = "https://auth.example.com/token"
)

func newTestRedis(t *testing.T) (*miniredis.Miniredis, *redis.Client) {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return mr, client
}

func defaultConfig() dpop.Config {
	return dpop.Config{
		JTIWindow:         5 * time.Minute,
		NonceTTL:          5 * time.Minute,
		MaxClockSkew:      60 * time.Second,
		AllowedAlgorithms: []string{"ES256", "EdDSA"},
	}
}

func newValidator(t *testing.T, cfg dpop.Config) (*dpop.Validator, *miniredis.Miniredis) {
	t.Helper()
	mr, rc := newTestRedis(t)
	v := dpop.NewValidator(cfg, rc, zap.NewNop())
	return v, mr
}

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

// buildProof creates a signed DPoP proof JWT for testing.
type proofBuilder struct {
	t       *testing.T
	header  map[string]interface{}
	claims  jwt.MapClaims
	signKey interface{}
	method  jwt.SigningMethod
}

func newES256ProofBuilder(t *testing.T, key *ecdsa.PrivateKey) *proofBuilder {
	t.Helper()
	pub := key.PublicKey
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := padLeftTest(pub.X.Bytes(), byteLen)
	yBytes := padLeftTest(pub.Y.Bytes(), byteLen)

	return &proofBuilder{
		t: t,
		header: map[string]interface{}{
			"typ": "dpop+jwt",
			"alg": "ES256",
			"jwk": map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(xBytes),
				"y":   base64.RawURLEncoding.EncodeToString(yBytes),
			},
		},
		claims: jwt.MapClaims{
			"jti": fmt.Sprintf("test-jti-%d", time.Now().UnixNano()),
			"htm": testMethod,
			"htu": testURL,
			"iat": float64(time.Now().Unix()),
		},
		signKey: key,
		method:  jwt.SigningMethodES256,
	}
}

func newEdDSAProofBuilder(t *testing.T, key ed25519.PrivateKey) *proofBuilder {
	t.Helper()
	pub := key.Public().(ed25519.PublicKey)

	return &proofBuilder{
		t: t,
		header: map[string]interface{}{
			"typ": "dpop+jwt",
			"alg": "EdDSA",
			"jwk": map[string]interface{}{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString([]byte(pub)),
			},
		},
		claims: jwt.MapClaims{
			"jti": fmt.Sprintf("test-jti-%d", time.Now().UnixNano()),
			"htm": testMethod,
			"htu": testURL,
			"iat": float64(time.Now().Unix()),
		},
		signKey: key,
		method:  jwt.SigningMethodEdDSA,
	}
}

func (b *proofBuilder) withJTI(jti string) *proofBuilder {
	b.claims["jti"] = jti
	return b
}

func (b *proofBuilder) withHTM(htm string) *proofBuilder {
	b.claims["htm"] = htm
	return b
}

func (b *proofBuilder) withHTU(htu string) *proofBuilder {
	b.claims["htu"] = htu
	return b
}

func (b *proofBuilder) withIAT(iat time.Time) *proofBuilder {
	b.claims["iat"] = float64(iat.Unix())
	return b
}

func (b *proofBuilder) withATH(ath string) *proofBuilder {
	b.claims["ath"] = ath
	return b
}

func (b *proofBuilder) withNonce(nonce string) *proofBuilder {
	b.claims["nonce"] = nonce
	return b
}

func (b *proofBuilder) withHeader(key string, value interface{}) *proofBuilder {
	b.header[key] = value
	return b
}

func (b *proofBuilder) withoutClaim(key string) *proofBuilder {
	delete(b.claims, key)
	return b
}

func (b *proofBuilder) withoutHeader(key string) *proofBuilder {
	delete(b.header, key)
	return b
}

func (b *proofBuilder) build() string {
	b.t.Helper()
	token := jwt.NewWithClaims(b.method, b.claims)
	for k, v := range b.header {
		token.Header[k] = v
	}
	signed, err := token.SignedString(b.signKey)
	require.NoError(b.t, err)
	return signed
}

func padLeftTest(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}

// ── ValidateProof tests ─────────────────────────────────────────────────────

func TestValidateProof_ES256_Success(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	key := generateES256Key(t)
	proofJWT := newES256ProofBuilder(t, key).build()

	proof, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
	require.NoError(t, err)
	assert.NotEmpty(t, proof.JWKThumbprint)
	assert.Equal(t, testMethod, proof.HTM)
	assert.Equal(t, testURL, proof.HTU)
	assert.NotEmpty(t, proof.JTI)
	assert.NotNil(t, proof.PublicKey)
}

func TestValidateProof_EdDSA_Success(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	key := generateEdDSAKey(t)
	proofJWT := newEdDSAProofBuilder(t, key).build()

	proof, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
	require.NoError(t, err)
	assert.NotEmpty(t, proof.JWKThumbprint)
	assert.Equal(t, testMethod, proof.HTM)
	assert.Equal(t, testURL, proof.HTU)
}

func TestValidateProof_Errors(t *testing.T) {
	tests := []struct {
		name       string
		buildProof func(t *testing.T) string
		method     string
		url        string
		token      string
		errContain string
	}{
		{
			name:       "invalid JWT",
			buildProof: func(_ *testing.T) string { return "not-a-jwt" },
			method:     testMethod,
			url:        testURL,
			errContain: "invalid_dpop_proof",
		},
		{
			name: "wrong typ header",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withHeader("typ", "JWT").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "typ must be dpop+jwt",
		},
		{
			name: "missing typ header",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutHeader("typ").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "typ must be dpop+jwt",
		},
		{
			name: "disallowed algorithm",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				// Build with ES256 but set header to claim RS256
				return newES256ProofBuilder(t, key).withHeader("alg", "RS256").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "not allowed",
		},
		{
			name: "missing jwk header",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutHeader("jwk").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "missing jwk header",
		},
		{
			name: "invalid jwk (not object)",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withHeader("jwk", "not-an-object").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "invalid jwk",
		},
		{
			name: "missing jti claim",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutClaim("jti").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "missing jti claim",
		},
		{
			name: "missing htm claim",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutClaim("htm").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "missing htm claim",
		},
		{
			name: "missing htu claim",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutClaim("htu").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "missing htu claim",
		},
		{
			name: "missing iat claim",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withoutClaim("iat").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "missing or invalid iat claim",
		},
		{
			name: "htm mismatch",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withHTM("GET").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "does not match HTTP method",
		},
		{
			name: "htu mismatch (different path)",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withHTU("https://auth.example.com/other").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "htu path",
		},
		{
			name: "htu mismatch (different host)",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withHTU("https://evil.example.com/token").build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "htu host",
		},
		{
			name: "iat in the future",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withIAT(time.Now().Add(5 * time.Minute)).build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "iat is in the future",
		},
		{
			name: "iat too old",
			buildProof: func(t *testing.T) string {
				key := generateES256Key(t)
				return newES256ProofBuilder(t, key).withIAT(time.Now().Add(-10 * time.Minute)).build()
			},
			method:     testMethod,
			url:        testURL,
			errContain: "iat is too old",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, _ := newValidator(t, defaultConfig())
			proofJWT := tt.buildProof(t)
			_, err := v.ValidateProof(context.Background(), proofJWT, tt.method, tt.url, tt.token)
			require.Error(t, err)
			assert.ErrorIs(t, err, dpop.ErrInvalidProof)
			assert.Contains(t, err.Error(), tt.errContain)
		})
	}
}

func TestValidateProof_ATH(t *testing.T) {
	t.Run("valid ath", func(t *testing.T) {
		v, _ := newValidator(t, defaultConfig())
		key := generateES256Key(t)
		accessToken := "qf_at_test-access-token" //nolint:gosec // test value
		ath := dpop.ComputeATH(accessToken)

		proofJWT := newES256ProofBuilder(t, key).withATH(ath).build()
		proof, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, accessToken)
		require.NoError(t, err)
		assert.Equal(t, ath, proof.AccessTokenHash)
	})

	t.Run("ath mismatch", func(t *testing.T) {
		v, _ := newValidator(t, defaultConfig())
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).withATH("wrong-ath").build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "qf_at_some-token")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ath mismatch")
	})

	t.Run("no ath required when no access token", func(t *testing.T) {
		v, _ := newValidator(t, defaultConfig())
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).build()

		proof, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.NoError(t, err)
		assert.Empty(t, proof.AccessTokenHash)
	})
}

func TestValidateProof_SignatureVerification(t *testing.T) {
	t.Run("wrong key in jwk", func(t *testing.T) {
		v, _ := newValidator(t, defaultConfig())
		signingKey := generateES256Key(t)
		differentKey := generateES256Key(t)

		// Build proof with differentKey's public key in the header but sign with signingKey
		pub := differentKey.PublicKey
		byteLen := (pub.Curve.Params().BitSize + 7) / 8
		xBytes := padLeftTest(pub.X.Bytes(), byteLen)
		yBytes := padLeftTest(pub.Y.Bytes(), byteLen)

		proofJWT := newES256ProofBuilder(t, signingKey).
			withHeader("jwk", map[string]interface{}{
				"kty": "EC",
				"crv": "P-256",
				"x":   base64.RawURLEncoding.EncodeToString(xBytes),
				"y":   base64.RawURLEncoding.EncodeToString(yBytes),
			}).
			build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "signature verification failed")
	})
}

// ── JTI Replay Protection ───────────────────────────────────────────────────

func TestValidateProof_JTIReplay(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	key := generateES256Key(t)

	jti := "unique-jti-for-replay-test"
	proofJWT1 := newES256ProofBuilder(t, key).withJTI(jti).build()

	// First use succeeds.
	_, err := v.ValidateProof(context.Background(), proofJWT1, testMethod, testURL, "")
	require.NoError(t, err)

	// Replay with same JTI fails.
	proofJWT2 := newES256ProofBuilder(t, key).withJTI(jti).build()
	_, err = v.ValidateProof(context.Background(), proofJWT2, testMethod, testURL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "jti already used")
}

// ── Nonce tests ─────────────────────────────────────────────────────────────

func TestValidateProof_NonceRequired(t *testing.T) {
	cfg := defaultConfig()
	cfg.NonceRequired = true

	t.Run("missing nonce returns use_dpop_nonce", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, dpop.ErrUseNonce)
	})

	t.Run("valid nonce accepted", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		ctx := context.Background()
		key := generateES256Key(t)

		nonce, err := v.GenerateNonce(ctx)
		require.NoError(t, err)

		proofJWT := newES256ProofBuilder(t, key).withNonce(nonce).build()
		proof, err := v.ValidateProof(ctx, proofJWT, testMethod, testURL, "")
		require.NoError(t, err)
		assert.Equal(t, nonce, proof.Nonce)
	})

	t.Run("invalid nonce returns use_dpop_nonce", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).withNonce("bogus-nonce").build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, dpop.ErrUseNonce)
	})

	t.Run("nonce is single-use", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		ctx := context.Background()
		key := generateES256Key(t)

		nonce, err := v.GenerateNonce(ctx)
		require.NoError(t, err)

		// First proof with nonce succeeds.
		proofJWT1 := newES256ProofBuilder(t, key).withNonce(nonce).build()
		_, err = v.ValidateProof(ctx, proofJWT1, testMethod, testURL, "")
		require.NoError(t, err)

		// Second proof with same nonce fails (nonce consumed).
		proofJWT2 := newES256ProofBuilder(t, key).withNonce(nonce).build()
		_, err = v.ValidateProof(ctx, proofJWT2, testMethod, testURL, "")
		require.Error(t, err)
		assert.ErrorIs(t, err, dpop.ErrUseNonce)
	})
}

func TestValidateProof_NonceOptional(t *testing.T) {
	cfg := defaultConfig()
	cfg.NonceRequired = false

	t.Run("no nonce is fine", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.NoError(t, err)
	})

	t.Run("valid voluntary nonce accepted", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		ctx := context.Background()
		key := generateES256Key(t)

		nonce, err := v.GenerateNonce(ctx)
		require.NoError(t, err)

		proofJWT := newES256ProofBuilder(t, key).withNonce(nonce).build()
		_, err = v.ValidateProof(ctx, proofJWT, testMethod, testURL, "")
		require.NoError(t, err)
	})

	t.Run("invalid voluntary nonce rejected", func(t *testing.T) {
		v, _ := newValidator(t, cfg)
		key := generateES256Key(t)
		proofJWT := newES256ProofBuilder(t, key).withNonce("bogus").build()

		_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid nonce")
	})
}

// ── GenerateNonce ───────────────────────────────────────────────────────────

func TestGenerateNonce(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	ctx := context.Background()

	nonce1, err := v.GenerateNonce(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce1)

	nonce2, err := v.GenerateNonce(ctx)
	require.NoError(t, err)
	assert.NotEmpty(t, nonce2)

	assert.NotEqual(t, nonce1, nonce2, "nonces must be unique")
}

// ── JWKThumbprint ───────────────────────────────────────────────────────────

func TestJWKThumbprint_EC(t *testing.T) {
	key := generateES256Key(t)
	tp, err := dpop.JWKThumbprint(&key.PublicKey)
	require.NoError(t, err)
	assert.NotEmpty(t, tp)

	// Same key produces same thumbprint (deterministic).
	tp2, err := dpop.JWKThumbprint(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, tp, tp2)

	// Different key produces different thumbprint.
	key2 := generateES256Key(t)
	tp3, err := dpop.JWKThumbprint(&key2.PublicKey)
	require.NoError(t, err)
	assert.NotEqual(t, tp, tp3)
}

func TestJWKThumbprint_EdDSA(t *testing.T) {
	key := generateEdDSAKey(t)
	pub := key.Public().(ed25519.PublicKey)
	tp, err := dpop.JWKThumbprint(pub)
	require.NoError(t, err)
	assert.NotEmpty(t, tp)

	// Deterministic.
	tp2, err := dpop.JWKThumbprint(pub)
	require.NoError(t, err)
	assert.Equal(t, tp, tp2)
}

// ── ComputeATH ──────────────────────────────────────────────────────────────

func TestComputeATH(t *testing.T) {
	token := "qf_at_test-access-token" //nolint:gosec // test value
	ath := dpop.ComputeATH(token)

	// Verify it's base64url(SHA-256(token)).
	hash := sha256.Sum256([]byte(token))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])
	assert.Equal(t, expected, ath)
}

// ── HTU matching ────────────────────────────────────────────────────────────

func TestValidateProof_HTU_IgnoresQueryAndFragment(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	key := generateES256Key(t)

	// Proof htu has no query, request URL has query — should still match.
	proofJWT := newES256ProofBuilder(t, key).
		withHTU("https://auth.example.com/token").
		build()

	_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, "https://auth.example.com/token?grant_type=authorization_code", "")
	require.NoError(t, err)
}

// ── Config defaults ─────────────────────────────────────────────────────────

func TestValidateProof_DefaultAlgorithms(t *testing.T) {
	cfg := dpop.Config{} // all zero values → defaults apply
	mr, rc := newTestRedis(t)
	_ = mr
	v := dpop.NewValidator(cfg, rc, zap.NewNop())

	// ES256 should be allowed by default.
	key := generateES256Key(t)
	proofJWT := newES256ProofBuilder(t, key).build()
	_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
	require.NoError(t, err)
}

// ── Edge cases ──────────────────────────────────────────────────────────────

func TestValidateProof_UnsupportedKeyType(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())

	// Build a proof with unsupported key type in jwk header.
	key := generateES256Key(t)
	proofJWT := newES256ProofBuilder(t, key).
		withHeader("jwk", map[string]interface{}{
			"kty": "RSA",
			"n":   "some-modulus",
			"e":   "AQAB",
		}).
		build()

	_, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported key type")
}

func TestValidateProof_ThumbprintInResult(t *testing.T) {
	v, _ := newValidator(t, defaultConfig())
	key := generateES256Key(t)
	proofJWT := newES256ProofBuilder(t, key).build()

	proof, err := v.ValidateProof(context.Background(), proofJWT, testMethod, testURL, "")
	require.NoError(t, err)

	// Thumbprint should match independent computation.
	expectedTP, err := dpop.JWKThumbprint(&key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, expectedTP, proof.JWKThumbprint)
}
