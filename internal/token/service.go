// Package token implements the token management service including
// JWT issuance, refresh, revocation, and JWKS endpoint.
package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	accessTokenPrefix = "qf_at_"

	// Default TTLs per client type when the client has no custom TTL.
	defaultServiceTTL = 15 * time.Minute
	defaultAgentTTL   = 5 * time.Minute
)

// ClientAuthenticator authenticates OAuth2 clients by ID and secret.
type ClientAuthenticator interface {
	AuthenticateClient(ctx context.Context, clientID uuid.UUID, secret string) (*domain.Client, error)
}

// Service implements api.TokenService.
type Service struct {
	clients    ClientAuthenticator
	signingKey crypto.Signer
	algorithm  string // "ES256" or "EdDSA"
	logger     *zap.Logger
}

// NewService creates a new token Service.
// It loads the private key from the path specified in cfg and validates
// that it matches the configured algorithm.
func NewService(clients ClientAuthenticator, cfg config.JWTConfig, logger *zap.Logger) (*Service, error) {
	key, err := loadPrivateKey(cfg.PrivateKeyPath, cfg.Algorithm)
	if err != nil {
		return nil, fmt.Errorf("load JWT private key: %w", err)
	}

	return &Service{
		clients:    clients,
		signingKey: key,
		algorithm:  cfg.Algorithm,
		logger:     logger,
	}, nil
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (s *Service) Refresh(_ context.Context, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): implement JWT refresh with token rotation.
	return nil, fmt.Errorf("token refresh not yet implemented: %w", api.ErrInternalError)
}

// ClientCredentials issues an access token for service-to-service authentication.
// It authenticates the client, validates requested scopes, and returns a JWT
// with a client_type claim. No refresh token is issued for this grant type.
func (s *Service) ClientCredentials(ctx context.Context, clientID, clientSecret string) (*api.AuthResult, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client_id: %w", api.ErrUnauthorized)
	}

	client, err := s.clients.AuthenticateClient(ctx, id, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("client authentication failed: %w", api.ErrUnauthorized)
	}

	ttl := clientTTL(client)
	now := time.Now().UTC()

	claims := jwt.MapClaims{
		"sub":         client.ID.String(),
		"client_type": string(client.ClientType),
		"scope":       strings.Join(client.Scopes, " "),
		"iat":         jwt.NewNumericDate(now),
		"exp":         jwt.NewNumericDate(now.Add(ttl)),
		"jti":         accessTokenPrefix + uuid.New().String(),
	}

	signingMethod := s.jwtSigningMethod()
	tok := jwt.NewWithClaims(signingMethod, claims)

	signed, err := tok.SignedString(s.signingKeyForSign())
	if err != nil {
		s.logger.Error("failed to sign JWT", zap.Error(err))
		return nil, fmt.Errorf("sign token: %w", api.ErrInternalError)
	}

	return &api.AuthResult{
		AccessToken: signed,
		TokenType:   "Bearer",
		ExpiresIn:   int(ttl.Seconds()),
	}, nil
}

// Revoke invalidates a token.
func (s *Service) Revoke(_ context.Context, _ string) error {
	// TODO(GH-XX): implement token revocation via Redis blocklist.
	return nil
}

// JWKS returns the JSON Web Key Set for token verification.
func (s *Service) JWKS(_ context.Context) (*api.JWKSResponse, error) {
	// TODO(GH-XX): implement JWKS from loaded public keys.
	return &api.JWKSResponse{Keys: []interface{}{}}, nil
}

// ValidateScopes checks that every requested scope is within the client's allowed scopes.
func ValidateScopes(requested, allowed []string) error {
	set := make(map[string]struct{}, len(allowed))
	for _, s := range allowed {
		set[s] = struct{}{}
	}
	var invalid []string
	for _, s := range requested {
		if _, ok := set[s]; !ok {
			invalid = append(invalid, s)
		}
	}
	if len(invalid) > 0 {
		return fmt.Errorf("scopes not allowed: %s: %w", strings.Join(invalid, ", "), api.ErrForbidden)
	}
	return nil
}

// clientTTL returns the access token TTL for the client.
// If the client has a custom TTL (AccessTokenTTL > 0), use it.
// Otherwise, fall back to type-specific defaults: 15min for service, 5min for agent.
func clientTTL(c *domain.Client) time.Duration {
	if c.AccessTokenTTL > 0 {
		return c.AccessTokenDuration()
	}
	switch c.ClientType {
	case domain.ClientTypeService:
		return defaultServiceTTL
	case domain.ClientTypeAgent:
		return defaultAgentTTL
	default:
		return defaultAgentTTL
	}
}

func (s *Service) jwtSigningMethod() jwt.SigningMethod {
	switch s.algorithm {
	case "EdDSA":
		return jwt.SigningMethodEdDSA
	default:
		return jwt.SigningMethodES256
	}
}

// signingKeyForSign returns the key in the form jwt.SignedString expects.
// For ECDSA: *ecdsa.PrivateKey; for EdDSA: ed25519.PrivateKey.
func (s *Service) signingKeyForSign() crypto.PrivateKey {
	return s.signingKey
}

// loadPrivateKey reads a PEM-encoded private key from disk and validates
// it matches the expected algorithm.
func loadPrivateKey(path, algorithm string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file %s: %w", path, err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("no PEM block found in key file")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try EC-specific parse as fallback.
		ecKey, ecErr := x509.ParseECPrivateKey(block.Bytes)
		if ecErr != nil {
			return nil, fmt.Errorf("parse private key: %w", err)
		}
		key = ecKey
	}

	switch algorithm {
	case "ES256":
		ecKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected ECDSA key for ES256, got %T", key)
		}
		return ecKey, nil
	case "EdDSA":
		edKey, ok := key.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("expected Ed25519 key for EdDSA, got %T", key)
		}
		return edKey, nil
	default:
		return nil, fmt.Errorf("unsupported algorithm: %s", algorithm)
	}
}
