package oauth

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
)

// Service implements api.OAuthService, orchestrating social login flows.
type Service struct {
	cfg config.OAuthConfig
	log *zap.Logger
}

// NewService creates an OAuth service.
func NewService(cfg config.OAuthConfig, log *zap.Logger) *Service {
	return &Service{cfg: cfg, log: log}
}

// GetAuthURL returns the authorization URL for the given provider.
func (s *Service) GetAuthURL(_ context.Context, provider, state, codeVerifier string) (string, error) {
	if !s.providerEnabled(provider) {
		return "", fmt.Errorf("provider %q not found: %w", provider, api.ErrNotFound)
	}
	// Provider-specific URL construction will be implemented in a follow-up issue.
	return "", fmt.Errorf("provider %q not implemented: %w", provider, api.ErrInternalError)
}

// HandleCallback exchanges an authorization code for tokens and links/creates the user account.
func (s *Service) HandleCallback(_ context.Context, provider, code, state string) (*api.OAuthCallbackResult, error) {
	if !s.providerEnabled(provider) {
		return nil, fmt.Errorf("provider %q not found: %w", provider, api.ErrNotFound)
	}
	return nil, fmt.Errorf("provider %q not implemented: %w", provider, api.ErrInternalError)
}

// ListLinkedProviders returns the OAuth providers linked to the given user.
func (s *Service) ListLinkedProviders(_ context.Context, _ string) ([]api.LinkedProvider, error) {
	return []api.LinkedProvider{}, nil
}

// UnlinkProvider removes the link between the user and the named provider.
func (s *Service) UnlinkProvider(_ context.Context, _, provider string) error {
	if !s.providerEnabled(provider) {
		return fmt.Errorf("provider %q not found: %w", provider, api.ErrNotFound)
	}
	return fmt.Errorf("provider %q not implemented: %w", provider, api.ErrInternalError)
}

func (s *Service) providerEnabled(provider string) bool {
	switch provider {
	case "google":
		return s.cfg.Google.Enabled
	case "github":
		return s.cfg.GitHub.Enabled
	case "apple":
		return s.cfg.Apple.Enabled
	default:
		return false
	}
}
