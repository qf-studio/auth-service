// Package token implements the token management service including
// JWT issuance, refresh, revocation, and JWKS endpoint.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	// accessTokenPrefix is prepended to JWT access tokens for leak detection.
	accessTokenPrefix = "qf_at_"

	// refreshTokenPrefix is prepended to refresh tokens for leak detection.
	refreshTokenPrefix = "qf_rt_"

	// proxyTokenPrefix is prepended to proxy tokens for leak detection.
	proxyTokenPrefix = "qf_px_"

	// revokedKeyPrefix is the Redis key prefix for the revocation blocklist.
	revokedKeyPrefix = "revoked:"

	// refreshKeyPrefix is the Redis key prefix for stored refresh token signatures.
	refreshKeyPrefix = "rt_sig:"

	// jtiBytes is the number of random bytes for JWT ID generation (16 bytes = 128 bits).
	jtiBytes = 16

	// refreshKeyBytes is the number of random bytes for the refresh token key part.
	refreshKeyBytes = 32

	// issuer is the JWT issuer claim value.
	issuer = "https://auth.qf.studio"
)

// Service implements api.TokenService and middleware.TokenValidator.
type Service struct {
	logger        *zap.Logger
	audit         audit.EventLogger
	redis         *redis.Client
	cfg           config.JWTConfig
	privateKey    crypto.Signer
	publicKey     crypto.PublicKey
	signingMethod jwt.SigningMethod
}

// NewService creates a new token Service, loading the private key from the
// path specified in cfg.PrivateKeyPath.
func NewService(cfg config.JWTConfig, redisClient *redis.Client, logger *zap.Logger, auditor audit.EventLogger) (*Service, error) {
	keyData, err := os.ReadFile(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}

	signer, pub, method, err := parsePrivateKey(keyData, cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &Service{
		logger:        logger,
		audit:         auditor,
		redis:         redisClient,
		cfg:           cfg,
		privateKey:    signer,
		publicKey:     pub,
		signingMethod: method,
	}, nil
}

// NewServiceFromKey creates a token Service from an already-parsed private key.
// Useful for testing without filesystem access.
func NewServiceFromKey(cfg config.JWTConfig, privateKey crypto.Signer, redisClient *redis.Client, logger *zap.Logger, auditor audit.EventLogger) (*Service, error) {
	pub := privateKey.Public()
	method, err := signingMethodForKey(privateKey, cfg.Algorithm)
	if err != nil {
		return nil, err
	}

	return &Service{
		logger:        logger,
		audit:         auditor,
		redis:         redisClient,
		cfg:           cfg,
		privateKey:    privateKey,
		publicKey:     pub,
		signingMethod: method,
	}, nil
}

// IssueTokenPair generates an access/refresh token pair for the given subject.
func (s *Service) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error) {
	return s.issueTokenPair(ctx, subject, roles, scopes, clientType, "")
}

// IssueTokenPairWithDPoP generates a DPoP-bound access/refresh token pair.
// The jktThumbprint is embedded as the cnf.jkt claim in the access token.
func (s *Service) IssueTokenPairWithDPoP(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint string) (*api.AuthResult, error) {
	return s.issueTokenPair(ctx, subject, roles, scopes, clientType, jktThumbprint)
}

func (s *Service) issueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint string) (*api.AuthResult, error) {
	accessToken, err := s.issueAccessToken(subject, roles, scopes, clientType, jktThumbprint)
	if err != nil {
		return nil, fmt.Errorf("issue access token: %w", err)
	}

	refreshToken, err := s.issueRefreshToken(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("issue refresh token: %w", err)
	}

	tokenType := "Bearer"
	if jktThumbprint != "" {
		tokenType = "DPoP"
	}

	return &api.AuthResult{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		TokenType:    tokenType,
		ExpiresIn:    int(s.cfg.AccessTokenTTL.Seconds()),
	}, nil
}

// IssueProxyToken creates a short-lived, audience-restricted proxy token.
// Used by the credential broker to grant temporary access to a specific target
// service without exposing the underlying credential.
func (s *Service) IssueProxyToken(ctx context.Context, subject string, audience string, scopes []string, ttl time.Duration) (string, error) {
	jti, err := generateRandomID(jtiBytes)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := &customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
			ID:        jti,
		},
		Scopes:     scopes,
		ClientType: string(domain.ClientTypeAgent),
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign proxy token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:    audit.EventBrokerAccess,
		ActorID: subject,
		Metadata: map[string]string{
			"audience": audience,
			"jti":      jti,
		},
	})

	return proxyTokenPrefix + signed, nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (s *Service) Refresh(ctx context.Context, rawRefreshToken string) (*api.AuthResult, error) {
	return s.refreshInternal(ctx, rawRefreshToken, "")
}

// RefreshWithDPoP exchanges a refresh token for a DPoP-bound access/refresh token pair.
func (s *Service) RefreshWithDPoP(ctx context.Context, rawRefreshToken, jktThumbprint string) (*api.AuthResult, error) {
	return s.refreshInternal(ctx, rawRefreshToken, jktThumbprint)
}

func (s *Service) refreshInternal(ctx context.Context, rawRefreshToken, jktThumbprint string) (*api.AuthResult, error) {
	subject, err := s.validateRefreshToken(ctx, rawRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
	}

	// Revoke the old refresh token (rotate).
	s.deleteRefreshToken(ctx, rawRefreshToken)

	// Issue new pair — refresh tokens carry no roles/scopes, so we issue with empty.
	// The caller (auth service) should enrich with user's current roles/scopes.
	result, err := s.issueTokenPair(ctx, subject, nil, nil, domain.ClientTypeUser, jktThumbprint)
	if err != nil {
		return nil, err
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRefresh,
		ActorID:  subject,
		TargetID: subject,
	})

	return result, nil
}

// ClientCredentials issues an access token for service-to-service authentication.
// Stub: client verification depends on client repository (future issue).
func (s *Service) ClientCredentials(_ context.Context, _, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): implement client credentials grant with client repository lookup.
	return nil, fmt.Errorf("client credentials not yet implemented: %w", api.ErrInternalError)
}

// ClientCredentialsWithDPoP issues a DPoP-bound access token for service-to-service auth.
// Stub: client verification depends on client repository (future issue).
func (s *Service) ClientCredentialsWithDPoP(_ context.Context, _, _, _ string) (*api.AuthResult, error) {
	return nil, fmt.Errorf("client credentials not yet implemented: %w", api.ErrInternalError)
}

// Revoke invalidates a token by adding its JTI to the Redis blocklist.
func (s *Service) Revoke(ctx context.Context, rawToken string) error {
	// Try as access token first.
	token := strings.TrimPrefix(rawToken, accessTokenPrefix)

	claims, err := s.parseJWT(token)
	if err != nil {
		// If not a valid JWT, just return success (RFC 7009: revoke is best-effort).
		s.logger.Debug("revoke: token is not a valid JWT, ignoring", zap.Error(err))
		return nil
	}

	jti, err := claims.GetJTI()
	if err != nil || jti == "" {
		return nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil || exp == nil {
		return nil
	}

	ttl := time.Until(exp.Time)
	if ttl <= 0 {
		// Already expired, no need to blocklist.
		return nil
	}

	key := revokedKeyPrefix + jti
	if err := s.redis.Set(ctx, key, "1", ttl).Err(); err != nil {
		s.logger.Error("failed to add token to revocation blocklist",
			zap.String("jti", jti),
			zap.Error(err),
		)
		return fmt.Errorf("revoke token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventTokenRevoke,
		Metadata: map[string]string{"jti": jti},
	})

	s.logger.Info("token revoked", zap.String("jti", jti), zap.Duration("ttl", ttl))
	return nil
}

// JWKS returns the JSON Web Key Set containing the public key for token verification.
func (s *Service) JWKS(_ context.Context) (*api.JWKSResponse, error) {
	jwk, err := publicKeyToJWK(s.publicKey, s.cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("build JWK: %w", err)
	}
	return &api.JWKSResponse{Keys: []interface{}{jwk}}, nil
}

// ValidateToken parses and cryptographically validates the raw JWT (qf_at_ prefix
// already stripped), returning its claims. Implements middleware.TokenValidator.
func (s *Service) ValidateToken(_ context.Context, rawToken string) (*domain.TokenClaims, error) {
	claims, err := s.parseAndVerifyJWT(rawToken)
	if err != nil {
		return nil, err
	}

	return claimsToDomain(claims)
}

// IsRevoked reports whether the token with the given JTI is present in the
// Redis revocation blocklist. Implements middleware.TokenValidator.
func (s *Service) IsRevoked(ctx context.Context, tokenID string) (bool, error) {
	key := revokedKeyPrefix + tokenID
	n, err := s.redis.Exists(ctx, key).Result()
	if err != nil {
		return false, fmt.Errorf("check revocation: %w", err)
	}
	return n > 0, nil
}

// ── Internal: Access Token ───────────────────────────────────────────────────

// Confirmation represents the cnf (confirmation) claim for DPoP-bound tokens (RFC 9449 §6).
type Confirmation struct {
	JKT string `json:"jkt"`
}

// customClaims extends jwt.RegisteredClaims with our application-specific fields.
type customClaims struct {
	jwt.RegisteredClaims
	Roles        []string      `json:"roles,omitempty"`
	Scopes       []string      `json:"scopes,omitempty"`
	ClientType   string        `json:"client_type"`
	Confirmation *Confirmation `json:"cnf,omitempty"`
}

// GetJTI is a helper to extract the JTI from RegisteredClaims.
func (c *customClaims) GetJTI() (string, error) {
	return c.ID, nil
}

func (s *Service) issueAccessToken(subject string, roles, scopes []string, clientType domain.ClientType, jktThumbprint string) (string, error) {
	jti, err := generateRandomID(jtiBytes)
	if err != nil {
		return "", fmt.Errorf("generate jti: %w", err)
	}

	now := time.Now()
	claims := &customClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   subject,
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(s.cfg.AccessTokenTTL)),
			ID:        jti,
		},
		Roles:      roles,
		Scopes:     scopes,
		ClientType: string(clientType),
	}

	if jktThumbprint != "" {
		claims.Confirmation = &Confirmation{JKT: jktThumbprint}
	}

	token := jwt.NewWithClaims(s.signingMethod, claims)
	signed, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}

	return accessTokenPrefix + signed, nil
}

func (s *Service) parseAndVerifyJWT(rawToken string) (*customClaims, error) {
	claims := &customClaims{}

	token, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		if t.Method.Alg() != s.signingMethod.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %s", t.Method.Alg())
		}
		return s.publicKey, nil
	}, jwt.WithValidMethods([]string{s.signingMethod.Alg()}))
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	return claims, nil
}

// parseJWT parses claims without strict validation (used for revocation to read jti/exp).
func (s *Service) parseJWT(rawToken string) (*customClaims, error) {
	claims := &customClaims{}

	_, err := jwt.ParseWithClaims(rawToken, claims, func(t *jwt.Token) (interface{}, error) {
		return s.publicKey, nil
	}, jwt.WithoutClaimsValidation())
	if err != nil {
		return nil, fmt.Errorf("parse JWT: %w", err)
	}

	return claims, nil
}

func claimsToDomain(c *customClaims) (*domain.TokenClaims, error) {
	if c.Subject == "" {
		return nil, fmt.Errorf("missing subject claim")
	}

	claims := &domain.TokenClaims{
		Subject:    c.Subject,
		Roles:      c.Roles,
		Scopes:     c.Scopes,
		ClientType: domain.ClientType(c.ClientType),
		TokenID:    c.ID,
	}

	if c.ExpiresAt != nil {
		claims.ExpiresAt = c.ExpiresAt.Time
	}
	if c.IssuedAt != nil {
		claims.IssuedAt = c.IssuedAt.Time
	}
	if c.Confirmation != nil {
		claims.JKTThumbprint = c.Confirmation.JKT
	}

	return claims, nil
}

// ── Internal: Refresh Token ──────────────────────────────────────────────────

func (s *Service) issueRefreshToken(ctx context.Context, subject string) (string, error) {
	if len(s.cfg.SystemSecrets) == 0 {
		return "", fmt.Errorf("no system secrets configured")
	}

	keyMaterial, err := generateRandomBytes(refreshKeyBytes)
	if err != nil {
		return "", fmt.Errorf("generate refresh key: %w", err)
	}

	keyEncoded := base64.RawURLEncoding.EncodeToString(keyMaterial)
	signature := hmacSign(keyMaterial, s.cfg.SystemSecrets[0])
	sigEncoded := base64.RawURLEncoding.EncodeToString(signature)

	refreshToken := refreshTokenPrefix + keyEncoded + "." + sigEncoded

	// Store the signature in Redis keyed by encoded key, with subject as value.
	redisKey := refreshKeyPrefix + keyEncoded
	if err := s.redis.Set(ctx, redisKey, subject, s.cfg.RefreshTokenTTL).Err(); err != nil {
		return "", fmt.Errorf("store refresh token: %w", err)
	}

	return refreshToken, nil
}

func (s *Service) validateRefreshToken(ctx context.Context, rawToken string) (string, error) {
	token := strings.TrimPrefix(rawToken, refreshTokenPrefix)

	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("malformed refresh token")
	}

	keyEncoded, sigEncoded := parts[0], parts[1]

	keyMaterial, err := base64.RawURLEncoding.DecodeString(keyEncoded)
	if err != nil {
		return "", fmt.Errorf("decode refresh key: %w", err)
	}

	sigBytes, err := base64.RawURLEncoding.DecodeString(sigEncoded)
	if err != nil {
		return "", fmt.Errorf("decode refresh signature: %w", err)
	}

	// Try each system secret (newest first) for rotation support.
	valid := false
	for _, secret := range s.cfg.SystemSecrets {
		expected := hmacSign(keyMaterial, secret)
		if hmac.Equal(sigBytes, expected) {
			valid = true
			break
		}
	}
	if !valid {
		return "", fmt.Errorf("invalid refresh token signature")
	}

	// Look up the subject from Redis.
	redisKey := refreshKeyPrefix + keyEncoded
	subject, err := s.redis.Get(ctx, redisKey).Result()
	if err == redis.Nil {
		return "", fmt.Errorf("refresh token not found or expired")
	}
	if err != nil {
		return "", fmt.Errorf("lookup refresh token: %w", err)
	}

	return subject, nil
}

func (s *Service) deleteRefreshToken(ctx context.Context, rawToken string) {
	token := strings.TrimPrefix(rawToken, refreshTokenPrefix)
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return
	}
	redisKey := refreshKeyPrefix + parts[0]
	if err := s.redis.Del(ctx, redisKey).Err(); err != nil {
		s.logger.Warn("failed to delete old refresh token", zap.Error(err))
	}
}

// ── Internal: Key Parsing ────────────────────────────────────────────────────

func parsePrivateKey(data []byte, algorithm string) (crypto.Signer, crypto.PublicKey, jwt.SigningMethod, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC-specific parse as fallback.
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, nil, nil, fmt.Errorf("parse private key (PKCS8: %v, EC: %v)", err, ecErr)
		}
		key = ecKey
	}

	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		if algorithm != "ES256" {
			return nil, nil, nil, fmt.Errorf("key is ECDSA but algorithm is %s", algorithm)
		}
		if k.Curve != elliptic.P256() {
			return nil, nil, nil, fmt.Errorf("ECDSA key must use P-256 curve for ES256")
		}
		return k, &k.PublicKey, jwt.SigningMethodES256, nil

	case ed25519.PrivateKey:
		if algorithm != "EdDSA" {
			return nil, nil, nil, fmt.Errorf("key is Ed25519 but algorithm is %s", algorithm)
		}
		return k, k.Public(), jwt.SigningMethodEdDSA, nil

	default:
		return nil, nil, nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

func signingMethodForKey(key crypto.Signer, algorithm string) (jwt.SigningMethod, error) {
	switch key.(type) {
	case *ecdsa.PrivateKey:
		if algorithm != "ES256" {
			return nil, fmt.Errorf("key is ECDSA but algorithm is %s", algorithm)
		}
		return jwt.SigningMethodES256, nil
	case ed25519.PrivateKey:
		if algorithm != "EdDSA" {
			return nil, fmt.Errorf("key is Ed25519 but algorithm is %s", algorithm)
		}
		return jwt.SigningMethodEdDSA, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}
}

// ── Internal: JWKS ───────────────────────────────────────────────────────────

// publicKeyToJWK converts a public key to a JWK map (RFC 7517).
func publicKeyToJWK(pub crypto.PublicKey, algorithm string) (map[string]interface{}, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("unsupported ECDSA curve")
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		xBytes := k.X.Bytes()
		yBytes := k.Y.Bytes()

		// Pad to fixed length.
		xPadded := make([]byte, byteLen)
		yPadded := make([]byte, byteLen)
		copy(xPadded[byteLen-len(xBytes):], xBytes)
		copy(yPadded[byteLen-len(yBytes):], yBytes)

		return map[string]interface{}{
			"kty": "EC",
			"crv": "P-256",
			"alg": algorithm,
			"use": "sig",
			"x":   base64.RawURLEncoding.EncodeToString(xPadded),
			"y":   base64.RawURLEncoding.EncodeToString(yPadded),
		}, nil

	case ed25519.PublicKey:
		return map[string]interface{}{
			"kty": "OKP",
			"crv": "Ed25519",
			"alg": algorithm,
			"use": "sig",
			"x":   base64.RawURLEncoding.EncodeToString([]byte(k)),
		}, nil

	default:
		return nil, fmt.Errorf("unsupported public key type: %T", pub)
	}
}

// ── Internal: Crypto Helpers ─────────────────────────────────────────────────

func hmacSign(data []byte, secret string) []byte {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(data)
	return h.Sum(nil)
}

func generateRandomID(n int) (string, error) {
	b, err := generateRandomBytes(n)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, fmt.Errorf("crypto/rand: %w", err)
	}
	return b, nil
}

// Ensure Service implements the required interfaces at compile time.
var _ api.TokenService = (*Service)(nil)
