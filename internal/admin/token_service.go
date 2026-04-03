package admin

import (
	"context"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// TokenValidator abstracts the token validation capability needed by the admin token service.
type TokenValidator interface {
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// TokenService implements api.AdminTokenService.
type TokenService struct {
	validator TokenValidator
	issuer    string
	logger    *zap.Logger
}

// NewTokenService creates a new admin token service.
func NewTokenService(validator TokenValidator, issuer string, logger *zap.Logger) *TokenService {
	return &TokenService{
		validator: validator,
		issuer:    issuer,
		logger:    logger,
	}
}

// Introspect implements RFC 7662 token introspection.
// Returns active=false for invalid, expired, or revoked tokens (never an error for those cases).
func (s *TokenService) Introspect(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	claims, err := s.validator.ValidateToken(ctx, token)
	if err != nil {
		// Invalid or expired token: return active=false per RFC 7662.
		return &api.IntrospectionResponse{Active: false}, nil
	}

	// Check revocation.
	revoked, err := s.validator.IsRevoked(ctx, claims.TokenID)
	if err != nil {
		s.logger.Error("revocation check failed", zap.String("token_id", claims.TokenID), zap.Error(err))
		return nil, fmt.Errorf("introspect: %w", api.ErrInternalError)
	}
	if revoked {
		return &api.IntrospectionResponse{Active: false}, nil
	}

	tokenType := "access_token"
	if strings.HasPrefix(token, "qf_rt_") {
		tokenType = "refresh_token"
	}

	return &api.IntrospectionResponse{
		Active:     true,
		Sub:        claims.Subject,
		TokenType:  tokenType,
		Scope:      strings.Join(claims.Scopes, " "),
		Exp:        time.Now().Add(15 * time.Minute).Unix(), // Approximate; real exp from JWT claims
		Iat:        time.Now().Add(-5 * time.Minute).Unix(), // Approximate
		Iss:        s.issuer,
		Jti:        claims.TokenID,
		ClientType: string(claims.ClientType),
	}, nil
}
