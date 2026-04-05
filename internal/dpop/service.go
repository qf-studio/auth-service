// Package dpop implements DPoP (Demonstrating Proof-of-Possession) proof
// validation per RFC 9449, including nonce issuance and JTI replay protection.
package dpop

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
)

const (
	// svcMaxClockSkew allows a small amount of clock drift for iat validation.
	svcMaxClockSkew = 30 * time.Second

	// svcMaxProofAge is the maximum age of a DPoP proof from issuance.
	svcMaxProofAge = 5 * time.Minute
)

// ProofClaims contains the validated claims extracted from a DPoP proof JWT.
type ProofClaims struct {
	// JKTThumbprint is the base64url-encoded SHA-256 thumbprint of the public key.
	JKTThumbprint string

	// HTTPMethod is the htm claim (e.g. "POST").
	HTTPMethod string

	// HTTPURI is the htu claim (e.g. "https://auth.qf.studio/auth/token").
	HTTPURI string
}

// Service validates DPoP proof JWTs, manages server nonces, and prevents JTI replay.
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

// Enabled reports whether DPoP is active.
func (s *Service) Enabled() bool {
	return s.cfg.Enabled
}

// ValidateProof validates a DPoP proof JWT per RFC 9449 §4.3.
// It verifies the proof structure, signature, htm/htu binding, timing, and JTI uniqueness.
// If nonce enforcement is desired, pass the expected nonce; empty string skips nonce check.
func (s *Service) ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (*ProofClaims, error) {
	// Parse the JWT header without verifying yet to extract the JWK.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, parts, err := parser.ParseUnverified(proofJWT, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse DPoP proof: %w", err)
	}

	// §4.3 step 1: typ must be "dpop+jwt".
	typ, _ := token.Header["typ"].(string)
	if !strings.EqualFold(typ, "dpop+jwt") {
		return nil, fmt.Errorf("invalid typ header: expected dpop+jwt, got %q", typ)
	}

	// §4.3 step 2: alg must be an asymmetric algorithm (not "none" or HMAC).
	alg, _ := token.Header["alg"].(string)
	if alg == "" || alg == "none" || strings.HasPrefix(alg, "HS") {
		return nil, fmt.Errorf("invalid alg: %q (must be asymmetric)", alg)
	}

	// §4.3 step 3: extract the jwk header and derive the public key.
	jwkRaw, ok := token.Header["jwk"]
	if !ok {
		return nil, fmt.Errorf("missing jwk header")
	}

	pubKey, err := parseJWK(jwkRaw)
	if err != nil {
		return nil, fmt.Errorf("parse jwk: %w", err)
	}

	// §4.3 step 4: verify the signature using the embedded public key.
	// Re-parse with proper verification.
	verifiedToken, err := jwt.Parse(proofJWT, func(t *jwt.Token) (interface{}, error) {
		return pubKey, nil
	}, jwt.WithValidMethods([]string{alg}))
	if err != nil {
		return nil, fmt.Errorf("verify DPoP signature: %w", err)
	}

	claims, ok := verifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("unexpected claims type")
	}

	// §4.3 step 5: check htm and htu.
	htm, _ := claims["htm"].(string)
	if !strings.EqualFold(htm, httpMethod) {
		return nil, fmt.Errorf("htm mismatch: expected %q, got %q", httpMethod, htm)
	}

	htu, _ := claims["htu"].(string)
	if htu != httpURI {
		return nil, fmt.Errorf("htu mismatch: expected %q, got %q", httpURI, htu)
	}

	// §4.3 step 6: check jti is present.
	jti, _ := claims["jti"].(string)
	if jti == "" {
		return nil, fmt.Errorf("missing jti claim")
	}

	// §4.3 step 7: check iat is within acceptable window.
	iatFloat, ok := claims["iat"].(float64)
	if !ok {
		return nil, fmt.Errorf("missing or invalid iat claim")
	}
	iat := time.Unix(int64(iatFloat), 0)
	now := time.Now()

	if now.Add(svcMaxClockSkew).Before(iat) {
		return nil, fmt.Errorf("DPoP proof issued in the future")
	}
	if now.Sub(iat) > svcMaxProofAge {
		return nil, fmt.Errorf("DPoP proof too old (issued %s ago)", now.Sub(iat))
	}

	// §4.3 step 9 (optional): check nonce if server nonce is present.
	if nonce, ok := claims["nonce"].(string); ok && nonce != "" {
		valid, nonceErr := s.validateNonce(ctx, nonce)
		if nonceErr != nil {
			return nil, fmt.Errorf("validate nonce: %w", nonceErr)
		}
		if !valid {
			return nil, fmt.Errorf("invalid or expired DPoP nonce")
		}
	}

	// JTI replay check.
	if err := s.checkAndStoreJTI(ctx, jti); err != nil {
		return nil, err
	}

	// Compute JWK thumbprint (RFC 7638).
	thumbprint, err := JWKThumbprint(pubKey)
	if err != nil {
		return nil, fmt.Errorf("compute JWK thumbprint: %w", err)
	}

	_ = parts // used by ParseUnverified

	return &ProofClaims{
		JKTThumbprint: thumbprint,
		HTTPMethod:    htm,
		HTTPURI:       htu,
	}, nil
}

// IssueNonce generates a server nonce and stores it in Redis with the configured TTL.
func (s *Service) IssueNonce(ctx context.Context) (string, error) {
	b := make([]byte, 32)
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

// validateNonce checks whether a nonce exists in Redis.
func (s *Service) validateNonce(ctx context.Context, nonce string) (bool, error) {
	key := nonceKeyPrefix + nonce
	n, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// checkAndStoreJTI ensures the JTI hasn't been seen within the replay window.
func (s *Service) checkAndStoreJTI(ctx context.Context, jti string) error {
	key := jtiKeyPrefix + jti
	set, err := s.redis.SetNX(ctx, key, "1", s.cfg.JTIWindow).Result()
	if err != nil {
		return fmt.Errorf("JTI replay check: %w", err)
	}
	if !set {
		return fmt.Errorf("DPoP proof JTI already used (replay)")
	}
	return nil
}


