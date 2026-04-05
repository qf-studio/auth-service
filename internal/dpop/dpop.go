// Package dpop implements DPoP (Demonstration of Proof-of-Possession) proof
// validation per RFC 9449. It provides JTI replay protection (Redis-backed),
// server nonce issuance, and JWK Thumbprint computation (RFC 7638).
package dpop

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"
)

const (
	// dpopType is the required typ header value for DPoP proofs.
	dpopType = "dpop+jwt"

	// jtiKeyPrefix is the Redis key prefix for DPoP proof JTI deduplication.
	jtiKeyPrefix = "dpop_jti:"

	// nonceKeyPrefix is the Redis key prefix for server-issued DPoP nonces.
	nonceKeyPrefix = "dpop_nonce:"

	// nonceBytes is the number of random bytes for nonce generation (16 bytes = 128 bits).
	nonceBytes = 16

	// defaultJTIWindow is the default deduplication window for DPoP proof JTIs.
	defaultJTIWindow = 5 * time.Minute

	// defaultNonceTTL is the default lifetime for server-issued nonces.
	defaultNonceTTL = 5 * time.Minute

	// defaultMaxClockSkew is the maximum allowed clock skew for iat validation.
	defaultMaxClockSkew = 60 * time.Second
)

// Error codes per RFC 9449 section 7.
var (
	ErrInvalidProof = fmt.Errorf("invalid_dpop_proof")
	ErrUseNonce     = fmt.Errorf("use_dpop_nonce")
)

// Config holds DPoP validation settings.
type Config struct {
	// NonceRequired requires a server-issued nonce in every DPoP proof.
	NonceRequired bool
	// JTIWindow is the deduplication window for proof JTIs (default: 5 min).
	JTIWindow time.Duration
	// NonceTTL is the lifetime for server-issued nonces (default: 5 min).
	NonceTTL time.Duration
	// MaxClockSkew is the maximum allowed clock skew for iat (default: 60s).
	MaxClockSkew time.Duration
	// AllowedAlgorithms lists permitted signing algorithms (default: ES256, EdDSA).
	AllowedAlgorithms []string
}

func (c Config) jtiWindow() time.Duration {
	if c.JTIWindow > 0 {
		return c.JTIWindow
	}
	return defaultJTIWindow
}

func (c Config) nonceTTL() time.Duration {
	if c.NonceTTL > 0 {
		return c.NonceTTL
	}
	return defaultNonceTTL
}

func (c Config) maxClockSkew() time.Duration {
	if c.MaxClockSkew > 0 {
		return c.MaxClockSkew
	}
	return defaultMaxClockSkew
}

func (c Config) allowedAlgorithms() []string {
	if len(c.AllowedAlgorithms) > 0 {
		return c.AllowedAlgorithms
	}
	return []string{"ES256", "EdDSA"}
}

// Proof represents a validated DPoP proof.
type Proof struct {
	// JWKThumbprint is the base64url-encoded SHA-256 JWK Thumbprint (RFC 7638).
	// Used as the cnf.jkt value when binding tokens.
	JWKThumbprint string
	// PublicKey is the client's public key extracted from the proof.
	PublicKey crypto.PublicKey
	// JTI is the unique identifier of the proof.
	JTI string
	// HTM is the HTTP method from the proof.
	HTM string
	// HTU is the HTTP URI from the proof.
	HTU string
	// IssuedAt is the proof creation time.
	IssuedAt time.Time
	// AccessTokenHash is the ath claim (base64url SHA-256 of access token), if present.
	AccessTokenHash string
	// Nonce is the server-issued nonce included in the proof, if any.
	Nonce string
}

// Validator validates DPoP proofs per RFC 9449.
type Validator struct {
	redis  *redis.Client
	logger *zap.Logger
	cfg    Config
}

// NewValidator creates a DPoP proof Validator.
func NewValidator(cfg Config, redisClient *redis.Client, logger *zap.Logger) *Validator {
	return &Validator{
		redis:  redisClient,
		logger: logger,
		cfg:    cfg,
	}
}

// proofClaims holds the extracted and validated claims from a DPoP proof JWT.
type proofClaims struct {
	jti   string
	htm   string
	htu   string
	iat   time.Time
	ath   string
	nonce string
}

// ValidateProof parses and validates a DPoP proof JWT per RFC 9449 section 4.3.
// httpMethod and httpURL must match the current request.
// accessToken may be empty for token-request proofs (where ath is not required).
func (v *Validator) ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURL, accessToken string) (*Proof, error) {
	// Parse, verify headers, extract public key, and verify signature.
	pubKey, claims, err := v.parseAndVerify(proofJWT)
	if err != nil {
		return nil, err
	}

	// Extract and validate all proof claims against the request context.
	pc, err := v.validateClaims(claims, httpMethod, httpURL, accessToken)
	if err != nil {
		return nil, err
	}

	// Nonce validation (server-issued, one-time use).
	if err := v.handleNonce(ctx, pc.nonce); err != nil {
		return nil, err
	}

	// JTI replay protection (Redis SetNX with TTL).
	if err := v.checkAndStoreJTI(ctx, pc.jti); err != nil {
		return nil, err
	}

	// Compute JWK Thumbprint (RFC 7638) for token binding.
	thumbprint, err := JWKThumbprint(pubKey)
	if err != nil {
		return nil, fmt.Errorf("%w: compute thumbprint: %v", ErrInvalidProof, err)
	}

	return &Proof{
		JWKThumbprint:   thumbprint,
		PublicKey:       pubKey,
		JTI:             pc.jti,
		HTM:             pc.htm,
		HTU:             pc.htu,
		IssuedAt:        pc.iat,
		AccessTokenHash: pc.ath,
		Nonce:           pc.nonce,
	}, nil
}

// parseAndVerify validates the JOSE headers (typ, alg, jwk) and verifies the
// proof signature with the embedded public key.
func (v *Validator) parseAndVerify(proofJWT string) (crypto.PublicKey, jwt.MapClaims, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	unverified, _, err := parser.ParseUnverified(proofJWT, jwt.MapClaims{})
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse failed: %v", ErrInvalidProof, err)
	}

	// Validate typ header.
	typ, _ := unverified.Header["typ"].(string)
	if !strings.EqualFold(typ, dpopType) {
		return nil, nil, fmt.Errorf("%w: typ must be dpop+jwt", ErrInvalidProof)
	}

	// Validate alg header is in the allowed list.
	alg, _ := unverified.Header["alg"].(string)
	if alg == "" {
		return nil, nil, fmt.Errorf("%w: missing alg header", ErrInvalidProof)
	}
	if !v.isAllowedAlgorithm(alg) {
		return nil, nil, fmt.Errorf("%w: algorithm %q not allowed", ErrInvalidProof, alg)
	}

	// Extract and parse the jwk header into a public key.
	jwkRaw, ok := unverified.Header["jwk"]
	if !ok {
		return nil, nil, fmt.Errorf("%w: missing jwk header", ErrInvalidProof)
	}
	pubKey, err := parseJWK(jwkRaw)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: invalid jwk: %v", ErrInvalidProof, err)
	}

	// Re-parse with full signature verification using the embedded public key.
	verified, err := jwt.Parse(proofJWT, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != alg {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}), jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: signature verification failed: %v", ErrInvalidProof, err)
	}

	claims, ok := verified.Claims.(jwt.MapClaims)
	if !ok {
		return nil, nil, fmt.Errorf("%w: invalid claims", ErrInvalidProof)
	}

	return pubKey, claims, nil
}

// validateClaims extracts and validates all required DPoP proof claims.
func (v *Validator) validateClaims(claims jwt.MapClaims, httpMethod, httpURL, accessToken string) (*proofClaims, error) {
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("%w: missing jti claim", ErrInvalidProof)
	}

	htm, _ := claims["htm"].(string)
	if htm == "" {
		return nil, fmt.Errorf("%w: missing htm claim", ErrInvalidProof)
	}

	htu, _ := claims["htu"].(string)
	if htu == "" {
		return nil, fmt.Errorf("%w: missing htu claim", ErrInvalidProof)
	}

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("%w: missing or invalid iat claim", ErrInvalidProof)
	}
	iat := time.Unix(int64(iatFloat), 0)

	// htm must match the HTTP method.
	if !strings.EqualFold(htm, httpMethod) {
		return nil, fmt.Errorf("%w: htm %q does not match HTTP method %q", ErrInvalidProof, htm, httpMethod)
	}

	// htu must match scheme + host + path (query/fragment ignored per RFC 9449).
	if err := matchHTU(htu, httpURL); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidProof, err)
	}

	// iat must be within acceptable time window.
	now := time.Now()
	skew := v.cfg.maxClockSkew()
	if iat.After(now.Add(skew)) {
		return nil, fmt.Errorf("%w: iat is in the future", ErrInvalidProof)
	}
	if iat.Before(now.Add(-v.cfg.jtiWindow())) {
		return nil, fmt.Errorf("%w: iat is too old", ErrInvalidProof)
	}

	// If access token provided, validate ath claim.
	ath, _ := claims["ath"].(string)
	if accessToken != "" {
		expectedATH := ComputeATH(accessToken)
		if ath != expectedATH {
			return nil, fmt.Errorf("%w: ath mismatch", ErrInvalidProof)
		}
	}

	nonce, _ := claims["nonce"].(string)

	return &proofClaims{
		jti:   jti,
		htm:   htm,
		htu:   htu,
		iat:   iat,
		ath:   ath,
		nonce: nonce,
	}, nil
}

// handleNonce validates the nonce claim based on the server's nonce policy.
func (v *Validator) handleNonce(ctx context.Context, nonce string) error {
	if v.cfg.NonceRequired {
		if nonce == "" {
			return ErrUseNonce
		}
		valid, err := v.validateNonce(ctx, nonce)
		if err != nil {
			return fmt.Errorf("%w: nonce check failed: %v", ErrInvalidProof, err)
		}
		if !valid {
			return ErrUseNonce
		}
		return nil
	}

	if nonce != "" {
		// Nonce provided voluntarily — still validate it.
		valid, err := v.validateNonce(ctx, nonce)
		if err != nil {
			v.logger.Warn("dpop nonce validation error", zap.Error(err))
		} else if !valid {
			return fmt.Errorf("%w: invalid nonce", ErrInvalidProof)
		}
	}
	return nil
}

// GenerateNonce creates a new server nonce and stores it in Redis.
// The nonce should be returned to the client via the DPoP-Nonce response header.
func (v *Validator) GenerateNonce(ctx context.Context) (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	nonce := base64.RawURLEncoding.EncodeToString(b)
	key := nonceKeyPrefix + nonce
	if err := v.redis.Set(ctx, key, "1", v.cfg.nonceTTL()).Err(); err != nil {
		return "", fmt.Errorf("store nonce: %w", err)
	}

	return nonce, nil
}

// JWKThumbprint computes the JWK Thumbprint per RFC 7638 using SHA-256.
// The result is base64url-encoded and suitable for use as a cnf.jkt claim.
func JWKThumbprint(pub crypto.PublicKey) (string, error) {
	var thumbprintInput string

	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return "", fmt.Errorf("unsupported EC curve for thumbprint")
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := padLeft(k.X.Bytes(), byteLen)
		yBytes := padLeft(k.Y.Bytes(), byteLen)
		// RFC 7638: members sorted lexicographically by key name.
		// String concatenation used intentionally to produce canonical JSON —
		// fmt.Sprintf %q adds Go-style escaping which breaks the canonical form.
		xEnc := base64.RawURLEncoding.EncodeToString(xBytes)
		yEnc := base64.RawURLEncoding.EncodeToString(yBytes)
		thumbprintInput = `{"crv":"P-256","kty":"EC","x":"` + xEnc + `","y":"` + yEnc + `"}`
	case ed25519.PublicKey:
		xEnc := base64.RawURLEncoding.EncodeToString([]byte(k))
		thumbprintInput = `{"crv":"Ed25519","kty":"OKP","x":"` + xEnc + `"}`
	default:
		return "", fmt.Errorf("unsupported key type for thumbprint: %T", pub)
	}

	hash := sha256.Sum256([]byte(thumbprintInput))
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// ComputeATH computes the base64url-encoded SHA-256 hash of an access token
// for the DPoP ath claim (RFC 9449 section 4.2).
func ComputeATH(accessToken string) string {
	hash := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

// ── Internal ────────────────────────────────────────────────────────────────

func (v *Validator) isAllowedAlgorithm(alg string) bool {
	for _, a := range v.cfg.allowedAlgorithms() {
		if a == alg {
			return true
		}
	}
	return false
}

// checkAndStoreJTI atomically checks for JTI replay and stores the JTI with TTL.
func (v *Validator) checkAndStoreJTI(ctx context.Context, jti string) error {
	key := jtiKeyPrefix + jti
	result, err := v.redis.SetArgs(ctx, key, "1", redis.SetArgs{
		Mode: "NX",
		TTL:  v.cfg.jtiWindow(),
	}).Result()
	if err == redis.Nil {
		return fmt.Errorf("%w: jti already used (replay)", ErrInvalidProof)
	}
	if err != nil {
		return fmt.Errorf("%w: jti check failed: %v", ErrInvalidProof, err)
	}
	_ = result
	return nil
}

// validateNonce checks whether a nonce exists in Redis and deletes it (one-time use).
func (v *Validator) validateNonce(ctx context.Context, nonce string) (bool, error) {
	key := nonceKeyPrefix + nonce
	n, err := v.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("check nonce: %w", err)
	}
	if n > 0 {
		// Nonces are single-use.
		v.redis.Del(ctx, key)
	}
	return n > 0, nil
}

// matchHTU validates that the htu claim matches the expected URL.
// Per RFC 9449 section 4.3: compare scheme, host, and path (ignore query and fragment).
func matchHTU(htu, expected string) error {
	htuParsed, err := url.Parse(htu)
	if err != nil {
		return fmt.Errorf("htu is not a valid URL: %v", err)
	}
	expParsed, err := url.Parse(expected)
	if err != nil {
		return fmt.Errorf("expected URL is not valid: %v", err)
	}

	if !strings.EqualFold(htuParsed.Scheme, expParsed.Scheme) {
		return fmt.Errorf("htu scheme %q does not match %q", htuParsed.Scheme, expParsed.Scheme)
	}
	if !strings.EqualFold(htuParsed.Host, expParsed.Host) {
		return fmt.Errorf("htu host %q does not match %q", htuParsed.Host, expParsed.Host)
	}
	if htuParsed.Path != expParsed.Path {
		return fmt.Errorf("htu path %q does not match %q", htuParsed.Path, expParsed.Path)
	}
	return nil
}

// parseJWK parses a JWK from the JWT header into a crypto.PublicKey.
// Only asymmetric key types (EC, OKP) are supported per RFC 9449.
func parseJWK(raw interface{}) (crypto.PublicKey, error) {
	jwkMap, ok := raw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jwk is not an object")
	}

	kty, _ := jwkMap["kty"].(string)
	switch kty {
	case "EC":
		return parseECPublicKey(jwkMap)
	case "OKP":
		return parseOKPPublicKey(jwkMap)
	default:
		return nil, fmt.Errorf("unsupported key type: %q", kty)
	}
}

func parseECPublicKey(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve: %q", crv)
	}

	xStr, _ := jwk["x"].(string)
	yStr, _ := jwk["y"].(string)
	if xStr == "" || yStr == "" {
		return nil, fmt.Errorf("missing x or y coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yStr)
	if err != nil {
		return nil, fmt.Errorf("decode y: %w", err)
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}

	if !pub.IsOnCurve(pub.X, pub.Y) {
		return nil, fmt.Errorf("EC point is not on curve")
	}

	return pub, nil
}

func parseOKPPublicKey(jwk map[string]interface{}) (ed25519.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %q", crv)
	}

	xStr, _ := jwk["x"].(string)
	if xStr == "" {
		return nil, fmt.Errorf("missing x coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xStr)
	if err != nil {
		return nil, fmt.Errorf("decode x: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key length: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

func padLeft(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	padded := make([]byte, size)
	copy(padded[size-len(b):], b)
	return padded
}
