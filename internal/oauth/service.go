package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// UserFinder abstracts looking up users by email for account linking.
type UserFinder interface {
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
}

// UserCreator abstracts creating new users from OAuth sign-ups.
type UserCreator interface {
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
}

// TokenIssuer abstracts token pair creation after successful OAuth login.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
}

// Config holds OAuth service-level settings.
type Config struct {
	StateSecret string // HMAC key for signing state tokens
}

// Service orchestrates the OAuth login flow: initiate, callback, account linking.
type Service struct {
	cfg      Config
	registry *Registry
	state    *StateManager
	accounts storage.OAuthAccountRepository
	users    UserFinder
	creator  UserCreator
	issuer   TokenIssuer
	logger   *zap.Logger
	audit    audit.EventLogger
}

// NewService creates a new OAuth service.
func NewService(
	cfg Config,
	registry *Registry,
	stateStore StateStore,
	accounts storage.OAuthAccountRepository,
	users UserFinder,
	creator UserCreator,
	issuer TokenIssuer,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		cfg:      cfg,
		registry: registry,
		state:    NewStateManager(cfg.StateSecret, stateStore),
		accounts: accounts,
		users:    users,
		creator:  creator,
		issuer:   issuer,
		logger:   logger,
		audit:    auditor,
	}
}

// AuthInitResult contains the URL and state needed to redirect the user.
type AuthInitResult struct {
	AuthURL      string `json:"auth_url"`
	State        string `json:"state"`
	CodeVerifier string `json:"-"` // kept server-side, not exposed to client
}

// InitiateAuth starts the OAuth flow: generates PKCE pair, creates signed state,
// and returns the provider's authorization URL.
func (s *Service) InitiateAuth(ctx context.Context, providerName string) (*AuthInitResult, error) {
	if !domain.IsValidOAuthProvider(providerName) {
		return nil, fmt.Errorf("unsupported oauth provider %q: %w", providerName, api.ErrNotFound)
	}

	provider, err := s.registry.Get(domain.OAuthProviderType(providerName))
	if err != nil {
		return nil, fmt.Errorf("get provider: %w", err)
	}

	pkce, err := GeneratePKCE()
	if err != nil {
		return nil, fmt.Errorf("generate pkce: %w", err)
	}

	stateToken, err := s.state.GenerateState(ctx, providerName, pkce.Verifier)
	if err != nil {
		return nil, fmt.Errorf("generate state: %w", err)
	}

	authURL := provider.GetAuthURL(stateToken, pkce.Challenge)

	return &AuthInitResult{
		AuthURL:      authURL,
		State:        stateToken,
		CodeVerifier: pkce.Verifier,
	}, nil
}

// HandleCallback processes the OAuth callback: validates state, exchanges code,
// fetches user profile, and either links to existing account or creates new user.
func (s *Service) HandleCallback(ctx context.Context, stateToken, code string) (*api.AuthResult, error) {
	// Validate and consume state (CSRF + replay protection).
	providerName, codeVerifier, err := s.state.ValidateState(ctx, stateToken)
	if err != nil {
		return nil, fmt.Errorf("invalid oauth state: %w", api.ErrUnauthorized)
	}

	provider, err := s.registry.Get(domain.OAuthProviderType(providerName))
	if err != nil {
		return nil, fmt.Errorf("get provider: %w", err)
	}

	// Exchange authorization code for access token.
	accessToken, err := provider.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	// Fetch user profile from provider.
	oauthUser, err := provider.GetUser(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("get oauth user: %w", err)
	}

	// Look for existing linked account.
	providerType := domain.OAuthProviderType(providerName)
	existingAccount, err := s.accounts.FindByProviderAndProviderUserID(ctx, providerType, oauthUser.ProviderUserID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("find oauth account: %w", err)
	}

	var userID string

	if existingAccount != nil {
		// Existing linked account — log in directly.
		userID = existingAccount.UserID
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventOAuthLogin,
			ActorID:  userID,
			TargetID: userID,
			Metadata: map[string]string{"provider": providerName},
		})
	} else {
		// No linked account — try account linking by email, or create new user.
		userID, err = s.linkOrCreateUser(ctx, providerType, oauthUser)
		if err != nil {
			return nil, err
		}
	}

	// Issue token pair.
	result, err := s.issuer.IssueTokenPair(ctx, userID, nil, nil, domain.ClientTypeUser)
	if err != nil {
		return nil, fmt.Errorf("issue tokens after oauth: %w", err)
	}
	result.UserID = userID

	return result, nil
}

// linkOrCreateUser tries to match by email first (account linking), then creates a new user.
func (s *Service) linkOrCreateUser(ctx context.Context, provider domain.OAuthProviderType, oauthUser *domain.OAuthUser) (string, error) {
	var userID string

	// Try account linking by email.
	if oauthUser.Email != "" {
		existingUser, err := s.users.FindByEmail(ctx, oauthUser.Email)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return "", fmt.Errorf("find user by email: %w", err)
		}
		if existingUser != nil {
			userID = existingUser.ID
			s.logger.Info("linking oauth account to existing user",
				zap.String("user_id", userID),
				zap.String("provider", string(provider)),
			)
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventOAuthLink,
				ActorID:  userID,
				TargetID: userID,
				Metadata: map[string]string{
					"provider": string(provider),
					"email":    oauthUser.Email,
				},
			})
		}
	}

	// No existing user found — create new user.
	if userID == "" {
		now := time.Now().UTC()
		newUser := &domain.User{
			ID:            uuid.New().String(),
			Email:         oauthUser.Email,
			Name:          oauthUser.Name,
			EmailVerified: oauthUser.Email != "",
			Roles:         []string{"user"},
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		created, err := s.creator.Create(ctx, newUser)
		if err != nil {
			if errors.Is(err, storage.ErrDuplicateEmail) {
				// Race condition: another request created the user between our check and insert.
				// Retry the lookup.
				existingUser, findErr := s.users.FindByEmail(ctx, oauthUser.Email)
				if findErr != nil {
					return "", fmt.Errorf("find user after duplicate: %w", findErr)
				}
				userID = existingUser.ID
			} else {
				return "", fmt.Errorf("create user from oauth: %w", err)
			}
		} else {
			userID = created.ID
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventOAuthNewUser,
				ActorID:  userID,
				TargetID: userID,
				Metadata: map[string]string{
					"provider": string(provider),
					"email":    oauthUser.Email,
				},
			})
		}
	}

	// Create the OAuth account link.
	now := time.Now().UTC()
	account := &domain.OAuthAccount{
		ID:             uuid.New().String(),
		UserID:         userID,
		Provider:       provider,
		ProviderUserID: oauthUser.ProviderUserID,
		Email:          oauthUser.Email,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if _, err := s.accounts.Create(ctx, account); err != nil {
		if errors.Is(err, storage.ErrDuplicateOAuthAccount) {
			// Another request linked this provider account concurrently — safe to proceed.
			s.logger.Info("oauth account already linked (concurrent)", zap.String("user_id", userID))
		} else {
			return "", fmt.Errorf("create oauth account link: %w", err)
		}
	}

	return userID, nil
}

// ListProviders returns the names of all registered (enabled) providers.
func (s *Service) ListProviders() []domain.OAuthProviderType {
	return s.registry.List()
}
