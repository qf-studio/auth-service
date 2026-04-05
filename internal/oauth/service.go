package oauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Audit event types for social login operations.
const (
	EventSocialLoginSuccess = "social_login_success"
	EventSocialLoginFailure = "social_login_failure"
	EventSocialAccountLink  = "social_account_link"
)

// UserRepository abstracts user persistence needed by the OAuth service.
type UserRepository interface {
	FindByEmail(ctx context.Context, email string) (*domain.User, error)
	Create(ctx context.Context, user *domain.User) (*domain.User, error)
}

// Config holds OAuth service-level settings.
type Config struct {
	StateHMACSecret string
	StateTTL        time.Duration
}

// DefaultConfig returns a default OAuth service configuration.
func DefaultConfig() Config {
	return Config{
		StateTTL: 10 * time.Minute,
	}
}

// Service orchestrates the OAuth authorization flow, including PKCE,
// state management, provider delegation, and account linking.
type Service struct {
	registry *Registry
	state    *StateManager
	users    UserRepository
	socials  storage.SocialAccountRepository
	logger   *zap.Logger
	audit    audit.EventLogger
}

// NewService creates a new OAuth service.
func NewService(
	registry *Registry,
	state *StateManager,
	users UserRepository,
	socials storage.SocialAccountRepository,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		registry: registry,
		state:    state,
		users:    users,
		socials:  socials,
		logger:   logger,
		audit:    auditor,
	}
}

// BeginAuthResult contains the data needed to redirect the user to the provider.
type BeginAuthResult struct {
	AuthURL      string
	CodeVerifier string
}

// BeginAuth starts the OAuth flow for the given provider.
// It generates PKCE parameters and a signed state token, then returns
// the authorization URL the user should be redirected to.
func (s *Service) BeginAuth(ctx context.Context, providerName domain.OAuthProvider) (*BeginAuthResult, error) {
	provider, err := s.registry.Get(providerName)
	if err != nil {
		return nil, fmt.Errorf("begin auth: %w", err)
	}

	codeVerifier, err := GenerateCodeVerifier()
	if err != nil {
		return nil, fmt.Errorf("begin auth: generate code verifier: %w", err)
	}

	state, err := s.state.Generate(ctx, string(providerName))
	if err != nil {
		return nil, fmt.Errorf("begin auth: generate state: %w", err)
	}

	authURL := provider.AuthCodeURL(state, codeVerifier)

	return &BeginAuthResult{
		AuthURL:      authURL,
		CodeVerifier: codeVerifier,
	}, nil
}

// CompleteAuthResult contains the user info from a completed OAuth flow.
type CompleteAuthResult struct {
	User          *domain.User
	SocialAccount *domain.SocialAccount
	IsNewUser     bool
}

// CompleteAuth finishes the OAuth flow: validates state, exchanges the code
// for user info, then finds or creates a user and links the social account.
func (s *Service) CompleteAuth(ctx context.Context, stateToken, code, codeVerifier string) (*CompleteAuthResult, error) {
	// Validate and consume the state token.
	providerName, err := s.state.Validate(ctx, stateToken)
	if err != nil {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSocialLoginFailure,
			Metadata: map[string]string{"reason": "invalid_state", "error": err.Error()},
		})
		return nil, fmt.Errorf("complete auth: validate state: %w", err)
	}

	provider, err := s.registry.Get(domain.OAuthProvider(providerName))
	if err != nil {
		return nil, fmt.Errorf("complete auth: %w", err)
	}

	// Exchange the authorization code for user info.
	userInfo, err := provider.ExchangeCode(ctx, code, codeVerifier)
	if err != nil {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSocialLoginFailure,
			Metadata: map[string]string{"provider": providerName, "reason": "code_exchange_failed"},
		})
		return nil, fmt.Errorf("complete auth: exchange code: %w", err)
	}

	if userInfo.Email == "" {
		return nil, fmt.Errorf("complete auth: provider returned no email")
	}

	// Account linking: find or create.
	result, err := s.findOrCreateUser(ctx, domain.OAuthProvider(providerName), userInfo)
	if err != nil {
		return nil, fmt.Errorf("complete auth: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventSocialLoginSuccess,
		ActorID:  result.User.ID,
		Metadata: map[string]string{"provider": providerName, "new_user": fmt.Sprintf("%t", result.IsNewUser)},
	})

	return result, nil
}

// findOrCreateUser looks up a user by the social account's provider+ID, falls
// back to email matching, and creates a new user if neither is found.
func (s *Service) findOrCreateUser(ctx context.Context, provider domain.OAuthProvider, info *domain.OAuthUserInfo) (*CompleteAuthResult, error) {
	// 1. Check if the social account already exists.
	existing, err := s.socials.FindByProviderUser(ctx, provider, info.ProviderUserID)
	if err == nil {
		// Social account exists — look up the linked user.
		user, userErr := s.users.FindByEmail(ctx, existing.Email)
		if userErr != nil {
			return nil, fmt.Errorf("find linked user: %w", userErr)
		}
		return &CompleteAuthResult{
			User:          user,
			SocialAccount: existing,
			IsNewUser:     false,
		}, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("lookup social account: %w", err)
	}

	// 2. Check if a user with this email already exists (link new social account).
	user, err := s.users.FindByEmail(ctx, info.Email)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("find user by email: %w", err)
	}

	isNewUser := false
	if errors.Is(err, storage.ErrNotFound) {
		// 3. Create a new user.
		now := time.Now().UTC()
		newUser := &domain.User{
			ID:            uuid.New().String(),
			Email:         info.Email,
			Name:          info.Name,
			Roles:         []string{"user"},
			EmailVerified: info.EmailVerified,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		user, err = s.users.Create(ctx, newUser)
		if err != nil {
			return nil, fmt.Errorf("create user: %w", err)
		}
		isNewUser = true
	}

	// 4. Link the social account.
	now := time.Now().UTC()
	account := &domain.SocialAccount{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		Provider:       provider,
		ProviderUserID: info.ProviderUserID,
		Email:          info.Email,
		Name:           info.Name,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	linked, err := s.socials.Link(ctx, account)
	if err != nil {
		return nil, fmt.Errorf("link social account: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventSocialAccountLink,
		ActorID:  user.ID,
		TargetID: linked.ID,
		Metadata: map[string]string{"provider": string(provider)},
	})

	return &CompleteAuthResult{
		User:          user,
		SocialAccount: linked,
		IsNewUser:     isNewUser,
	}, nil
}

// GetRegistry returns the underlying provider registry for inspection.
func (s *Service) GetRegistry() *Registry {
	return s.registry
}
