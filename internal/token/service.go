// Package token implements the token management service including
// JWT issuance, refresh, revocation, and JWKS endpoint.
package token

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
)

// Service implements api.TokenService.
// Stub: full JWT implementation depends on key management and user repository (future issues).
type Service struct {
	logger *zap.Logger
}

// NewService creates a new token Service.
func NewService(logger *zap.Logger) *Service {
	return &Service{logger: logger}
}

// Refresh exchanges a refresh token for a new access/refresh token pair.
func (s *Service) Refresh(_ context.Context, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): implement JWT refresh with token rotation.
	return nil, fmt.Errorf("token refresh not yet implemented: %w", api.ErrInternalError)
}

// ClientCredentials issues an access token for service-to-service authentication.
func (s *Service) ClientCredentials(_ context.Context, _, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): implement client credentials grant.
	return nil, fmt.Errorf("client credentials not yet implemented: %w", api.ErrInternalError)
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
