// Package dpop implements DPoP (Demonstration of Proof-of-Possession) proof
// validation per RFC 9449. It verifies DPoP proof JWTs, manages server nonces,
// and prevents JTI replay attacks using Redis.
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
	"encoding/json"
	"fmt"
	"math/big"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
)

const (
	// dpopType is the required typ header for DPoP proof JWTs (RFC 9449 §4.2).
	dpopType = "dpop+jwt"

	// jtiKeyPrefix is the Redis key prefix for DPoP proof JTI replay detection.
	jtiKeyPrefix = "dpop_jti:"

	// nonceKeyPrefix is the Redis key prefix for server-issued DPoP nonces.
	nonceKeyPrefix = "dpop_nonce:"

	// nonceBytes is the number of random bytes for nonce generation.
	nonceBytes = 32

	// maxClockSkew is the allowed clock skew for DPoP proof iat validation.
	maxClockSkew = 30 * time.Second
)

// ProofClaims holds the validated claims from a DPoP proof JWT.
type ProofClaims struct {
	// JWKThumbprint is the SHA-256 thumbprint of the public key in the proof's JWK header.
	JWKThumbprint string

	// HTTPMethod is the htm claim (HTTP method the proof is bound to).
	HTTPMethod string

	// HTTPURI is the htu claim (HTTP URI the proof is bound to).
	HTTPURI string

	// JTI is the unique identifier for replay detection.
	JTI string

	// IssuedAt is the iat claim.
	IssuedAt time.Time

	// AccessTokenHash is the ath claim (hash of the access token), if present.
	AccessTokenHash string

	// Nonce is the server-provided nonce, if present.
	Nonce string
}

// Service implements DPoP proof validation and nonce management.
type Service struct {
	logger *zap.Logger
	redis  *redis.Client
	cfg    config.DPoPConfig
}

// NewService creates a new DPoP service.
func NewService(cfg config.DPoPConfig, redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		logger: logger,
		redis:  redisClient,
		cfg:    cfg,
	}
}

// Enabled reports whether DPoP is enabled.
func (s *Service) Enabled() bool {
	return s.cfg.Enabled
}

// ValidateProof validates a DPoP proof JWT against the expected HTTP method and URI.
// It verifies the proof structure, signature, JTI uniqueness, and timing.
func (s *Service) ValidateProof(ctx context.Context, proof, httpMethod, httpURI string) (*ProofClaims, error) {
	// Parse header to extract JWK without verifying signature yet.
	token, parts, err := new(jwt.Parser).ParseUnverified(proof, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse DPoP proof: %w", err)
	}

	// Validate typ header.
	typ, _ := token.Header["typ"].(string)
	if !strings.EqualFold(typ, dpopType) {
		return nil, fmt.Errorf("invalid DPoP proof typ: %q", typ)
	}

	// Must not have kid — the key is embedded as jwk header.
	if _, hasKid := token.Header["kid"]; hasKid {
		return nil, fmt.Errorf("DPoP proof must not contain kid header")
	}

	// Extract and parse JWK from header.
	jwkRaw, ok := token.Header["jwk"]
	if !ok {
		return nil, fmt.Errorf("DPoP proof missing jwk header")
	}

	pubKey, err := parseJWK(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("parse DPoP proof jwk: %w", err)
	}

	// Now verify the signature with the extracted public key.
	signingMethod := token.Method
	if err := signingMethod.Verify(strings.Join(parts[:2], "."), decodeSegment(parts[2]), pubKey); err != nil {
		return nil, fmt.Errorf("DPoP proof signature verification failed: %w", err)
	}

	// Extract claims.
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid DPoP proof claims")
	}

	// Validate required claims.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("DPoP proof missing jti claim")
	}

	htm, _ := claims["htm"].(string)
	if htm == "" {
		return nil, fmt.Errorf("DPoP proof missing htm claim")
	}

	htu, _ := claims["htu"].(string)
	if htu == "" {
		return nil, fmt.Errorf("DPoP proof missing htu claim")
	}

	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("DPoP proof missing or invalid iat claim")
	}
	iat := time.Unix(int64(iatFloat), 0)

	// Validate htm matches expected.
	if !strings.EqualFold(htm, httpMethod) {
		return nil, fmt.Errorf("DPoP proof htm %q does not match request method %q", htm, httpMethod)
	}

	// Validate htu matches expected (compare without query/fragment).
	if !matchesHTU(htu, httpURI) {
		return nil, fmt.Errorf("DPoP proof htu %q does not match request URI %q", htu, httpURI)
	}

	// Validate iat is within acceptable window.
	now := time.Now()
	if iat.After(now.Add(maxClockSkew)) {
		return nil, fmt.Errorf("DPoP proof iat is in the future")
	}
	if iat.Before(now.Add(-s.cfg.JTIWindow - maxClockSkew)) {
		return nil, fmt.Errorf("DPoP proof iat is too old")
	}

	// Check JTI replay.
	jtiKey := jtiKeyPrefix + jti
	set, err := s.redis.SetNX(ctx, jtiKey, "1", s.cfg.JTIWindow+maxClockSkew).Result()
	if err != nil {
		return nil, fmt.Errorf("check DPoP jti replay: %w", err)
	}
	if !set {
		return nil, fmt.Errorf("DPoP proof jti already used (replay)")
	}

	// Compute JWK thumbprint (RFC 7638).
	thumbprint, err := computeJWKThumbprint(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	result := &ProofClaims{
		JWKThumbprint: thumbprint,
		HTTPMethod:    htm,
		HTTPURI:       htu,
		JTI:           jti,
		IssuedAt:      iat,
	}

	if ath, ok := claims["ath"].(string); ok {
		result.AccessTokenHash = ath
	}
	if nonce, ok := claims["nonce"].(string); ok {
		result.Nonce = nonce
	}

	return result, nil
}

// IssueNonce generates and stores a server nonce for DPoP.
func (s *Service) IssueNonce(ctx context.Context) (string, error) {
	b := make([]byte, nonceBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)

	key := nonceKeyPrefix + nonce
	if err := s.redis.Set(ctx, key, "1", s.cfg.NonceTTL).Err(); err != nil {
		return "", fmt.Errorf("store nonce: %w", err)
	}

	return nonce, nil
}

// ValidateNonce checks if a nonce is valid (was issued by this server and not expired).
func (s *Service) ValidateNonce(ctx context.Context, nonce string) (bool, error) {
	key := nonceKeyPrefix + nonce
	n, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("validate nonce: %w", err)
	}
	return n > 0, nil
}

// ComputeAccessTokenHash computes the ath claim value (base64url-encoded SHA-256 of the access token).
func ComputeAccessTokenHash(accessToken string) string {
	h := sha256.Sum256([]byte(accessToken))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

// ── Internal helpers ────────────────────────────────────────────────────────

// parseJWK parses a JWK map from the DPoP proof header into a crypto public key.
func parseJWK(jwkRaw interface{}) (crypto.PublicKey, error) {
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("jwk header is not a JSON object")
	}

	kty, _ := jwkMap["kty"].(string)
	switch kty {
	case "EC":
		return parseECJWK(jwkMap)
	case "OKP":
		return parseOKPJWK(jwkMap)
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %q", kty)
	}
}

func parseECJWK(jwk map[string]interface{}) (*ecdsa.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "P-256" {
		return nil, fmt.Errorf("unsupported EC curve: %q (only P-256 allowed)", crv)
	}

	xB64, _ := jwk["x"].(string)
	yB64, _ := jwk["y"].(string)
	if xB64 == "" || yB64 == "" {
		return nil, fmt.Errorf("EC JWK missing x or y coordinates")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC x: %w", err)
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(yB64)
	if err != nil {
		return nil, fmt.Errorf("decode EC y: %w", err)
	}

	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}, nil
}

func parseOKPJWK(jwk map[string]interface{}) (ed25519.PublicKey, error) {
	crv, _ := jwk["crv"].(string)
	if crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %q (only Ed25519 allowed)", crv)
	}

	xB64, _ := jwk["x"].(string)
	if xB64 == "" {
		return nil, fmt.Errorf("OKP JWK missing x coordinate")
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(xB64)
	if err != nil {
		return nil, fmt.Errorf("decode OKP x: %w", err)
	}

	if len(xBytes) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: %d", len(xBytes))
	}

	return ed25519.PublicKey(xBytes), nil
}

// computeJWKThumbprint computes the JWK Thumbprint per RFC 7638 using SHA-256.
func computeJWKThumbprint(jwkRaw interface{}) (string, error) {
	jwkMap, ok := jwkRaw.(map[string]interface{})
	if !ok {
		return "", fmt.Errorf("jwk is not a JSON object")
	}

	kty, _ := jwkMap["kty"].(string)

	// Build the canonical JSON representation per RFC 7638 §3.2.
	// Only the required members in lexicographic order.
	var canonical []byte
	var err error

	switch kty {
	case "EC":
		canonical, err = json.Marshal(map[string]string{
			"crv": jwkMap["crv"].(string),
			"kty": kty,
			"x":   jwkMap["x"].(string),
			"y":   jwkMap["y"].(string),
		})
	case "OKP":
		canonical, err = json.Marshal(map[string]string{
			"crv": jwkMap["crv"].(string),
			"kty": kty,
			"x":   jwkMap["x"].(string),
		})
	default:
		return "", fmt.Errorf("unsupported kty for thumbprint: %q", kty)
	}

	if err != nil {
		return "", fmt.Errorf("marshal canonical JWK: %w", err)
	}

	hash := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// decodeSegment decodes a base64url JWT segment.
func decodeSegment(seg string) []byte {
	b, _ := base64.RawURLEncoding.DecodeString(seg)
	return b
}

// matchesHTU compares the htu claim with the request URI.
// Per RFC 9449, htu should match scheme + authority + path (no query/fragment).
func matchesHTU(htu, requestURI string) bool {
	// Strip query and fragment from both for comparison.
	htu = stripQueryFragment(htu)
	requestURI = stripQueryFragment(requestURI)
	return htu == requestURI
}

func stripQueryFragment(u string) string {
	if i := strings.IndexByte(u, '?'); i >= 0 {
		u = u[:i]
	}
	if i := strings.IndexByte(u, '#'); i >= 0 {
		u = u[:i]
	}
	return u
}
