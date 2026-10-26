package oidc

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oauth"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ProviderService implements api.OIDCProviderService: the OAuth2/OIDC
// authorization server operations (discovery, authorize, token exchange,
// userinfo). The interactive login/consent decisions are handled separately
// by ConsentService; ProviderService.Authorize only ever produces a redirect
// to the external login UI.
type ProviderService struct {
	cfg        config.OIDCConfig
	signingAlg string
	store      Store
	clients    ClientLookup
	users      UserLookup
	tokens     TokenIssuer
	hasher     password.Hasher
	logger     *zap.Logger
	audit      audit.EventLogger
}

// NewProviderService creates a new ProviderService. signingAlg is the JWT
// signing algorithm used by tokens (cfg.JWT.Algorithm, e.g. "ES256" or
// "EdDSA"), surfaced in the discovery document.
func NewProviderService(
	cfg config.OIDCConfig,
	signingAlg string,
	store Store,
	clients ClientLookup,
	users UserLookup,
	tokens TokenIssuer,
	hasher password.Hasher,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *ProviderService {
	return &ProviderService{
		cfg:        cfg,
		signingAlg: signingAlg,
		store:      store,
		clients:    clients,
		users:      users,
		tokens:     tokens,
		hasher:     hasher,
		logger:     logger,
		audit:      auditor,
	}
}

// Compile-time assertion that ProviderService satisfies api.OIDCProviderService.
var _ api.OIDCProviderService = (*ProviderService)(nil)

// GetDiscovery returns the OpenID Connect discovery document (RFC 8414 / OIDC
// Discovery 1.0), built from cfg.OIDC and the route constants in routes.go.
func (s *ProviderService) GetDiscovery(_ context.Context) (*api.OIDCDiscoveryResponse, error) {
	issuer := strings.TrimSuffix(s.cfg.IssuerURL, "/")
	return &api.OIDCDiscoveryResponse{
		Issuer:                            issuer,
		AuthorizationEndpoint:             issuer + RouteAuthorize,
		TokenEndpoint:                     issuer + RouteToken,
		UserinfoEndpoint:                  issuer + RouteUserInfo,
		JwksURI:                           issuer + RouteJWKS,
		ScopesSupported:                   s.cfg.SupportedScopes,
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{s.signingAlg},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
	}, nil
}

// Authorize initiates the authorization code flow. It validates the client
// and redirect_uri (returning a JSON error, not a redirect, if either is
// invalid — the redirect_uri is not trusted yet), then creates a
// LoginRequest and returns a redirect to the external login UI. Once
// redirect_uri has been validated, all further validation errors (bad
// response_type, PKCE violations) are reported as a *successful*
// AuthorizeResponse whose RedirectTo carries `?error=...` per RFC 6749
// §4.1.2.1, since only the caller's registered redirect_uri is a safe place
// to send error details.
func (s *ProviderService) Authorize(ctx context.Context, req *api.AuthorizeRequest) (*api.AuthorizeResponse, error) {
	if s.cfg.LoginUIURL == "" {
		s.logger.Error("authorize: OIDC_LOGIN_UI_URL not configured")
		return nil, fmt.Errorf("oidc provider misconfigured: %w", api.ErrInternalError)
	}

	tenantID := domain.TenantIDFromContext(ctx)

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("unknown client_id: %w", api.ErrNotFound)
	}
	client, err := s.clients.FindByID(ctx, tenantID, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", req.ClientID, api.ErrNotFound)
		}
		s.logger.Error("authorize: find client failed", zap.Error(err))
		return nil, fmt.Errorf("authorize: %w", api.ErrInternalError)
	}
	if !client.IsActive() {
		return nil, fmt.Errorf("client %s is not active: %w", req.ClientID, api.ErrNotFound)
	}
	if !exactRedirectURIMatch(client.RedirectURIs, req.RedirectURI) {
		return nil, fmt.Errorf("unregistered redirect_uri: %w", api.ErrNotFound)
	}

	// redirect_uri is now trusted; report all further errors via redirect.
	if req.ResponseType != "code" {
		return &api.AuthorizeResponse{RedirectTo: buildRedirectError(
			req.RedirectURI, "unsupported_response_type", "only response_type=code is supported", req.State,
		)}, nil
	}

	// Decision: PKCE is mandatory for every client type, confidential
	// included (OAuth 2.1 §4.1.1), so an intercepted code is useless without
	// the verifier.
	if req.CodeChallenge == "" {
		return &api.AuthorizeResponse{RedirectTo: buildRedirectError(
			req.RedirectURI, "invalid_request", "code_challenge is required", req.State,
		)}, nil
	}
	if req.CodeChallengeMethod != "S256" {
		// Covers both an omitted method (which per RFC 7636 defaults to
		// "plain") and an explicit "plain": this provider is S256-only.
		return &api.AuthorizeResponse{RedirectTo: buildRedirectError(
			req.RedirectURI, "invalid_request", "only code_challenge_method=S256 is supported", req.State,
		)}, nil
	}

	// Decision: unknown / unpermitted scopes are dropped rather than rejected
	// (RFC 6749 §3.3 lets the server issue fewer scopes than requested); only
	// a missing openid scope is fatal, since this is an OIDC provider.
	scopes := grantableScopes(splitScope(req.Scope), s.cfg.SupportedScopes, client.Scopes)
	if !containsScope(scopes, "openid") {
		return &api.AuthorizeResponse{RedirectTo: buildRedirectError(
			req.RedirectURI, "invalid_scope", "the openid scope is required and must be permitted for this client", req.State,
		)}, nil
	}

	challenge, err := generateID(challengeIDBytes)
	if err != nil {
		s.logger.Error("authorize: generate challenge failed", zap.Error(err))
		return nil, fmt.Errorf("authorize: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()
	lr := &LoginRequest{
		Challenge:           challenge,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scopes:              scopes,
		State:               req.State,
		Nonce:               req.Nonce,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: req.CodeChallengeMethod,
		RequestedAt:         now,
		ExpiresAt:           now.Add(defaultChallengeTTL),
	}
	if err := s.store.SaveLoginRequest(ctx, lr); err != nil {
		s.logger.Error("authorize: save login request failed", zap.Error(err))
		return nil, fmt.Errorf("authorize: %w", api.ErrInternalError)
	}

	loginURL, err := appendQueryParam(s.cfg.LoginUIURL, "login_challenge", challenge)
	if err != nil {
		s.logger.Error("authorize: build login redirect failed", zap.Error(err))
		return nil, fmt.Errorf("authorize: %w", api.ErrInternalError)
	}

	return &api.AuthorizeResponse{RedirectTo: loginURL}, nil
}

// ExchangeCode redeems a one-time authorization code for a token pair (and,
// for the openid scope, an ID token).
func (s *ProviderService) ExchangeCode(ctx context.Context, req *api.CodeExchangeRequest) (*api.OIDCTokenResponse, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("unknown client_id: %w", api.ErrUnauthorized)
	}
	client, err := s.clients.FindByID(ctx, tenantID, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", req.ClientID, api.ErrUnauthorized)
		}
		s.logger.Error("exchange code: find client failed", zap.Error(err))
		return nil, fmt.Errorf("exchange code: %w", api.ErrInternalError)
	}
	if !client.IsActive() {
		return nil, fmt.Errorf("client %s is not active: %w", req.ClientID, api.ErrUnauthorized)
	}

	isPublic := client.ClientType == domain.ClientTypePublic
	if !isPublic {
		if req.ClientSecret == "" || !s.verifyClientSecret(client, req.ClientSecret) {
			return nil, fmt.Errorf("invalid client credentials: %w", api.ErrUnauthorized)
		}
	}

	code, err := s.store.ConsumeAuthorizationCode(ctx, req.Code)
	if err != nil {
		if errors.Is(err, ErrAuthorizationCodeNotFound) {
			return nil, fmt.Errorf("invalid or expired authorization code: %w", api.ErrUnauthorized)
		}
		s.logger.Error("exchange code: consume code failed", zap.Error(err))
		return nil, fmt.Errorf("exchange code: %w", api.ErrInternalError)
	}

	if code.ClientID != req.ClientID {
		return nil, fmt.Errorf("authorization code was not issued to this client: %w", api.ErrUnauthorized)
	}
	if code.RedirectURI != req.RedirectURI {
		return nil, fmt.Errorf("redirect_uri mismatch: %w", api.ErrUnauthorized)
	}

	if code.CodeChallenge == "" {
		// Defense in depth: Authorize requires PKCE for every client, so a
		// code without a challenge should never reach here.
		return nil, fmt.Errorf("authorization code has no code_challenge: %w", api.ErrUnauthorized)
	}
	if req.CodeVerifier == "" || oauth.S256Challenge(req.CodeVerifier) != code.CodeChallenge {
		return nil, fmt.Errorf("code_verifier does not match code_challenge: %w", api.ErrUnauthorized)
	}

	user, err := s.users.FindByID(ctx, tenantID, code.Subject)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", code.Subject, api.ErrUnauthorized)
		}
		s.logger.Error("exchange code: find user failed", zap.Error(err))
		return nil, fmt.Errorf("exchange code: %w", api.ErrInternalError)
	}
	// The user may have been locked or deleted after the code was issued.
	if !user.IsActive() {
		return nil, fmt.Errorf("user %s is not active: %w", code.Subject, api.ErrUnauthorized)
	}

	// GH-541: a refresh token is issued only when offline_access was granted
	// (OIDC Core §11). Decision: the check uses the granted code.Scopes, never
	// the raw request.
	// GH-512: when it is issued, persist the client id alongside it (via
	// IssueTokenPairForClient instead of IssueTokenPair) so a later refresh
	// can re-resolve this client's Audience rather than falling back to the
	// global JWT_AUDIENCE.
	issue := s.tokens.IssueAccessTokenForClient
	if containsScope(code.Scopes, "offline_access") {
		issue = s.tokens.IssueTokenPairForClient
	}
	result, err := issue(ctx, user.ID, user.Roles, code.Scopes, domain.ClientTypeUser, req.ClientID, client.Audience...)
	if err != nil {
		s.logger.Error("exchange code: issue tokens failed", zap.Error(err))
		return nil, fmt.Errorf("exchange code: %w", api.ErrInternalError)
	}

	resp := &api.OIDCTokenResponse{
		AccessToken:  result.AccessToken,
		TokenType:    result.TokenType,
		ExpiresIn:    result.ExpiresIn,
		RefreshToken: result.RefreshToken,
		Scope:        joinScopes(code.Scopes),
	}

	if containsScope(code.Scopes, "openid") {
		idToken, err := s.tokens.IssueIDToken(ctx, user.ID, req.ClientID, code.Nonce, code.AuthTime)
		if err != nil {
			s.logger.Error("exchange code: issue id token failed", zap.Error(err))
			return nil, fmt.Errorf("exchange code: %w", api.ErrInternalError)
		}
		resp.IDToken = idToken
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventOIDCCodeExchange,
		ActorID:  user.ID,
		TargetID: req.ClientID,
	})

	return resp, nil
}

// verifyClientSecret checks secret against both the current secret_hash and,
// if within its grace period, the previous_secret_hash (see
// PostgresClientRepository.RotateSecret).
func (s *ProviderService) verifyClientSecret(client *domain.Client, secret string) bool {
	if client.SecretHash != "" {
		if ok, err := s.hasher.Verify(secret, client.SecretHash); err == nil && ok {
			return true
		}
	}
	if client.PreviousSecretHash != "" && client.PreviousSecretExpiresAt != nil &&
		time.Now().UTC().Before(*client.PreviousSecretExpiresAt) {
		if ok, err := s.hasher.Verify(secret, client.PreviousSecretHash); err == nil && ok {
			return true
		}
	}
	return false
}

// GetUserInfo returns claims about the authenticated user (OIDC Core §5.3),
// projected by the scopes on the presented access token: the token must carry
// openid (else api.ErrInsufficientScope); email and email_verified require
// the email scope, name requires the profile scope. sub is always returned.
func (s *ProviderService) GetUserInfo(ctx context.Context, userID string, scopes []string) (*api.OIDCUserInfoResponse, error) {
	if !containsScope(scopes, "openid") {
		return nil, fmt.Errorf("userinfo requires the openid scope: %w", api.ErrInsufficientScope)
	}

	tenantID := domain.TenantIDFromContext(ctx)
	user, err := s.users.FindByID(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user %s: %w", userID, api.ErrNotFound)
		}
		s.logger.Error("userinfo: find user failed", zap.Error(err))
		return nil, fmt.Errorf("userinfo: %w", api.ErrInternalError)
	}

	resp := &api.OIDCUserInfoResponse{Sub: user.ID}
	if containsScope(scopes, "email") {
		resp.Email = user.Email
		resp.EmailVerified = user.EmailVerified
	}
	if containsScope(scopes, "profile") {
		resp.Name = user.Name
	}
	return resp, nil
}
