// Package oauth provides social login and OIDC provider support.
package oauth

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Provider defines the operations that each OAuth provider must implement.
type Provider interface {
	// Name returns the provider identifier (e.g. "google", "github", "apple").
	Name() string
	// GetAuthURL returns the authorization URL the user should be redirected to.
	GetAuthURL(ctx context.Context) (string, error)
	// ExchangeCode exchanges an authorization code for user information.
	ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error)
}

// Service orchestrates OAuth authentication flows.
type Service struct {
	providers map[string]Provider
	repo      storage.OAuthAccountRepository
	tokenSvc  api.TokenService
	stateMgr  *StateManager
	log       *zap.Logger
}

// NewService creates a new OAuth service with the given enabled providers.
func NewService(
	cfg config.OAuthConfig,
	repo storage.OAuthAccountRepository,
	tokenSvc api.TokenService,
	log *zap.Logger,
	stateMgr *StateManager,
	providers ...Provider,
) *Service {
	pm := make(map[string]Provider, len(providers))
	for _, p := range providers {
		pm[p.Name()] = p
	}

	enabledNames := make([]string, 0, len(pm))
	for name := range pm {
		enabledNames = append(enabledNames, name)
	}
	if len(enabledNames) > 0 {
		log.Info("OAuth providers registered", zap.Strings("providers", enabledNames))
	}

	return &Service{
		providers: pm,
		repo:      repo,
		tokenSvc:  tokenSvc,
		stateMgr:  stateMgr,
		log:       log,
	}
}

// GetAuthURL returns the authorization URL for the given provider.
func (s *Service) GetAuthURL(ctx context.Context, provider string) (*domain.OAuthAuthURL, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", api.ErrNotFound, domain.ErrOAuthProviderNotSupported.Error())
	}

	url, err := p.GetAuthURL(ctx)
	if err != nil {
		s.log.Error("failed to get OAuth auth URL", zap.String("provider", provider), zap.Error(err))
		return nil, fmt.Errorf("get auth URL: %w", err)
	}

	return &domain.OAuthAuthURL{AuthURL: url}, nil
}

// HandleCallback exchanges an authorization code for user info and issues a JWT pair.
func (s *Service) HandleCallback(ctx context.Context, provider, code, state string) (*api.AuthResult, error) {
	p, ok := s.providers[provider]
	if !ok {
		return nil, fmt.Errorf("%w: %s", api.ErrNotFound, domain.ErrOAuthProviderNotSupported.Error())
	}

	// Validate the signed state parameter and extract the embedded PKCE verifier.
	if s.stateMgr != nil && state != "" {
		verifier, err := s.stateMgr.Validate(state)
		if err != nil {
			s.log.Warn("OAuth state validation failed",
				zap.String("provider", provider),
				zap.Error(err),
			)
			return nil, fmt.Errorf("%w: %v", api.ErrUnauthorized, domain.ErrOAuthStateMismatch)
		}
		ctx = WithCodeVerifier(ctx, verifier)
	}

	oauthUser, err := p.ExchangeCode(ctx, code)
	if err != nil {
		s.log.Error("OAuth code exchange failed",
			zap.String("provider", provider),
			zap.Error(err),
		)
		return nil, fmt.Errorf("%w: %v", api.ErrUnauthorized, domain.ErrOAuthCodeExchangeFailed)
	}

	// Look up existing linked account.
	existing, err := s.repo.FindByProviderAndProviderUserID(ctx, provider, oauthUser.ProviderUserID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("find oauth account: %w", err)
	}

	if existing != nil {
		s.log.Info("OAuth login for existing linked account",
			zap.String("provider", provider),
			zap.String("user_id", existing.UserID),
		)
		// Return a placeholder result — actual token issuance depends on
		// integration with the auth service (implemented in a subsequent issue).
		return &api.AuthResult{
			UserID: existing.UserID,
		}, nil
	}

	// No linked account found — the full account creation/linking flow
	// is handled in a subsequent issue. Return an error for now.
	s.log.Info("OAuth callback for unlinked provider user",
		zap.String("provider", provider),
		zap.String("provider_user_id", oauthUser.ProviderUserID),
	)
	return nil, fmt.Errorf("%w: no linked account for this provider user", api.ErrNotFound)
}

// ListLinkedAccounts returns all OAuth accounts linked to a user.
func (s *Service) ListLinkedAccounts(ctx context.Context, userID string) (*domain.OAuthLinkedAccounts, error) {
	accounts, err := s.repo.FindByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list linked accounts: %w", err)
	}

	return &domain.OAuthLinkedAccounts{Accounts: accounts}, nil
}

// UnlinkAccount removes the OAuth link for the specified provider.
func (s *Service) UnlinkAccount(ctx context.Context, userID, provider string) error {
	err := s.repo.Delete(ctx, userID, provider)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("%w: %s", api.ErrNotFound, domain.ErrOAuthAccountNotFound.Error())
		}
		return fmt.Errorf("unlink oauth account: %w", err)
	}

	s.log.Info("OAuth account unlinked",
		zap.String("user_id", userID),
		zap.String("provider", provider),
	)
	return nil
}
