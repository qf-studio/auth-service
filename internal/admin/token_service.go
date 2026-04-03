package admin

import (
	"context"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// TokenValidator abstracts the token validation capability needed by the admin token service.
type TokenValidator interface {
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// RefreshTokenLookup abstracts DB lookup for refresh token introspection.
type RefreshTokenLookup interface {
	FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)
}

// TokenService implements api.AdminTokenService.
type TokenService struct {
	validator     TokenValidator
	refreshTokens RefreshTokenLookup
	issuer        string
	logger        *zap.Logger
}

// NewTokenService creates a new admin token service.
// refreshTokens may be nil; when nil, refresh token introspection returns active=false.
func NewTokenService(validator TokenValidator, refreshTokens RefreshTokenLookup, issuer string, logger *zap.Logger) *TokenService {
	return &TokenService{
		validator:     validator,
		refreshTokens: refreshTokens,
		issuer:        issuer,
		logger:        logger,
	}
}

// Introspect implements RFC 7662 token introspection.
//
//   - Access tokens (qf_at_ prefix): validated via JWT decode; revocation checked via Redis.
//   - Refresh tokens (qf_rt_ prefix): validated via DB lookup.
//
// Returns active=false for invalid, expired, or revoked tokens (never an error for those cases).
func (s *TokenService) Introspect(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	if strings.HasPrefix(token, "qf_rt_") {
		return s.introspectRefreshToken(ctx, token)
	}
	return s.introspectAccessToken(ctx, token)
}

// introspectAccessToken validates a JWT access token (qf_at_ prefix accepted).
func (s *TokenService) introspectAccessToken(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	// Strip prefix so ValidateToken receives a bare JWT.
	rawJWT := strings.TrimPrefix(token, "qf_at_")

	claims, err := s.validator.ValidateToken(ctx, rawJWT)
	if err != nil {
		// Invalid or expired token: active=false per RFC 7662.
		return &api.IntrospectionResponse{Active: false}, nil
	}

	revoked, err := s.validator.IsRevoked(ctx, claims.TokenID)
	if err != nil {
		s.logger.Error("revocation check failed", zap.String("token_id", claims.TokenID), zap.Error(err))
		return nil, fmt.Errorf("introspect: %w", api.ErrInternalError)
	}
	if revoked {
		return &api.IntrospectionResponse{Active: false}, nil
	}

	resp := &api.IntrospectionResponse{
		Active:     true,
		Sub:        claims.Subject,
		TokenType:  "access_token",
		Scope:      strings.Join(claims.Scopes, " "),
		Iss:        s.issuer,
		Jti:        claims.TokenID,
		ClientType: string(claims.ClientType),
	}
	if !claims.ExpiresAt.IsZero() {
		resp.Exp = claims.ExpiresAt.Unix()
	}
	if !claims.IssuedAt.IsZero() {
		resp.Iat = claims.IssuedAt.Unix()
	}

	return resp, nil
}

// introspectRefreshToken looks up a refresh token record in the DB.
// Token format: qf_rt_<keyEncoded>.<sigEncoded>
// The signature (sigEncoded) is the DB lookup key.
func (s *TokenService) introspectRefreshToken(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	if s.refreshTokens == nil {
		return &api.IntrospectionResponse{Active: false}, nil
	}

	// Strip prefix and split into key + signature parts.
	raw := strings.TrimPrefix(token, "qf_rt_")
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[1] == "" {
		return &api.IntrospectionResponse{Active: false}, nil
	}
	signature := parts[1]

	rec, err := s.refreshTokens.FindBySignature(ctx, signature)
	if err != nil {
		// Not found or other lookup error: return active=false, not an error to the caller.
		s.logger.Debug("refresh token lookup failed during introspect", zap.Error(err))
		return &api.IntrospectionResponse{Active: false}, nil
	}

	if rec.IsRevoked() || rec.IsExpired() {
		return &api.IntrospectionResponse{Active: false}, nil
	}

	return &api.IntrospectionResponse{
		Active:    true,
		Sub:       rec.UserID,
		TokenType: "refresh_token",
		Exp:       rec.ExpiresAt.Unix(),
		Iat:       rec.CreatedAt.Unix(),
		Iss:       s.issuer,
	}, nil
}

// Ensure TokenService implements the interface at compile time.
var _ api.AdminTokenService = (*TokenService)(nil)
