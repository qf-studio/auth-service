package admin

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	accessTokenPrefix  = "qf_at_"
	refreshTokenPrefix = "qf_rt_"
)

// TokenService implements api.AdminTokenService for RFC 7662 token introspection.
type TokenService struct {
	validator     TokenValidator
	refreshFinder RefreshTokenFinder
}

// NewTokenService creates a new admin TokenService.
func NewTokenService(validator TokenValidator, refreshFinder RefreshTokenFinder) *TokenService {
	return &TokenService{validator: validator, refreshFinder: refreshFinder}
}

// Introspect determines whether a token is active and returns its metadata.
// Access tokens (qf_at_) are introspected via JWT decode.
// Refresh tokens (qf_rt_) are introspected via database lookup.
// Unknown token formats return {active: false} per RFC 7662.
func (s *TokenService) Introspect(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	switch {
	case strings.HasPrefix(token, accessTokenPrefix):
		return s.introspectAccessToken(ctx, strings.TrimPrefix(token, accessTokenPrefix))
	case strings.HasPrefix(token, refreshTokenPrefix):
		return s.introspectRefreshToken(ctx, token)
	default:
		return &api.IntrospectionResponse{Active: false}, nil
	}
}

// introspectAccessToken validates the raw JWT and maps claims to an IntrospectionResponse.
// Per RFC 7662, an invalid or expired token returns {active: false} without an error.
func (s *TokenService) introspectAccessToken(ctx context.Context, rawJWT string) (*api.IntrospectionResponse, error) {
	claims, err := s.validator.ValidateToken(ctx, rawJWT)
	if err != nil {
		// Invalid, expired, or malformed — return inactive per RFC 7662 §2.2.
		return &api.IntrospectionResponse{Active: false}, nil
	}

	return &api.IntrospectionResponse{
		Active:     true,
		Sub:        claims.Subject,
		ClientType: string(claims.ClientType),
		TokenType:  "access_token",
		Scope:      strings.Join(claims.Scopes, " "),
		Jti:        claims.TokenID,
	}, nil
}

// introspectRefreshToken looks up the full refresh token string in the database
// and returns its active status and metadata.
func (s *TokenService) introspectRefreshToken(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	rec, err := s.refreshFinder.FindBySignature(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return &api.IntrospectionResponse{Active: false, TokenType: "refresh_token"}, nil
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	active := !rec.IsRevoked() && !rec.IsExpired()

	resp := &api.IntrospectionResponse{
		Active:    active,
		TokenType: "refresh_token",
	}

	if active {
		resp.Sub = rec.UserID
		resp.Exp = rec.ExpiresAt.Unix()
		resp.Iat = rec.CreatedAt.Unix()
	}

	return resp, nil
}

// Compile-time assertion.
var _ api.AdminTokenService = (*TokenService)(nil)
