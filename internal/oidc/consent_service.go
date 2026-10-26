package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ConsentService implements api.ConsentService: the Hydra-style external
// login/consent admin API consumed by the login and consent UIs to resolve
// LoginRequest/ConsentRequest challenges created by ProviderService.Authorize.
type ConsentService struct {
	cfg     config.OIDCConfig
	store   Store
	clients ClientLookup
	users   UserLookup
	grants  ConsentGrantStore
	logger  *zap.Logger
	audit   audit.EventLogger
}

// NewConsentService creates a new ConsentService.
func NewConsentService(
	cfg config.OIDCConfig,
	store Store,
	clients ClientLookup,
	users UserLookup,
	grants ConsentGrantStore,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *ConsentService {
	return &ConsentService{
		cfg:     cfg,
		store:   store,
		clients: clients,
		users:   users,
		grants:  grants,
		logger:  logger,
		audit:   auditor,
	}
}

// Compile-time assertion that ConsentService satisfies api.ConsentService.
var _ api.ConsentService = (*ConsentService)(nil)

// GetLoginRequest returns details of a pending login request for display by
// the login UI. Non-destructive: the UI may poll this repeatedly while the
// user authenticates.
func (s *ConsentService) GetLoginRequest(ctx context.Context, challenge string) (*api.LoginRequestInfo, error) {
	lr, err := s.store.GetLoginRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrLoginRequestNotFound) {
			return nil, fmt.Errorf("login request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("get login request failed", zap.Error(err))
		return nil, fmt.Errorf("get login request: %w", api.ErrInternalError)
	}

	return &api.LoginRequestInfo{
		Challenge:  lr.Challenge,
		ClientID:   lr.ClientID,
		Scope:      joinScopes(lr.Scopes),
		RequestURL: buildRequestURL(lr),
	}, nil
}

// AcceptLogin consumes the login request (one-time use) and authenticates
// req.Subject against it. If the client is first-party, or the subject has
// an active remembered consent grant covering the requested scopes, an
// authorization code is issued immediately and the consent screen is
// skipped. Otherwise a ConsentRequest is created and the caller is
// redirected to the external consent UI.
//
// req.Remember (persistent browser SSO session) has no effect: this
// codebase has no durable login-session store to back it, only per-request
// login challenges. It is accepted for interface compatibility.
func (s *ConsentService) AcceptLogin(ctx context.Context, challenge string, req *api.AcceptLoginRequest) (*api.RedirectResponse, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	lr, err := s.store.ConsumeLoginRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrLoginRequestNotFound) {
			return nil, fmt.Errorf("login request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("accept login: consume login request failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}

	clientID, err := uuid.Parse(lr.ClientID)
	if err != nil {
		s.logger.Error("accept login: invalid client_id in stored login request", zap.String("client_id", lr.ClientID), zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}
	client, err := s.clients.FindByID(ctx, tenantID, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", lr.ClientID, api.ErrNotFound)
		}
		s.logger.Error("accept login: find client failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}

	if !client.IsActive() {
		return nil, fmt.Errorf("client %s is not active: %w", lr.ClientID, api.ErrForbidden)
	}

	// The login UI is trusted to authenticate req.Subject, but not to name
	// an account that is unknown, locked, suspended or deleted: no code may
	// be issued for one.
	user, err := s.users.FindByID(ctx, tenantID, req.Subject)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("subject %s: %w", req.Subject, api.ErrNotFound)
		}
		s.logger.Error("accept login: find subject failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}
	if !user.IsActive() {
		return nil, fmt.Errorf("subject %s is not active: %w", req.Subject, api.ErrForbidden)
	}

	now := time.Now().UTC()

	skipConsent := !isThirdParty(client)
	if !skipConsent {
		grant, err := s.grants.FindActive(ctx, tenantID, req.Subject, clientID)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			s.logger.Error("accept login: find active consent grant failed", zap.Error(err))
			return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
		}
		if grant != nil && grant.IsActive() && grant.CoversScopes(lr.Scopes) {
			skipConsent = true
		}
	}

	if skipConsent {
		redirectTo, err := s.issueCode(ctx, lr.ClientID, lr.RedirectURI, req.Subject, lr.Scopes, lr.Nonce, lr.CodeChallenge, lr.CodeChallengeMethod, lr.State, now)
		if err != nil {
			return nil, err
		}
		s.auditLoginAccept(ctx, req.Subject, lr.ClientID, challenge, true)
		return &api.RedirectResponse{RedirectTo: redirectTo}, nil
	}

	consentChallenge, err := generateID(challengeIDBytes)
	if err != nil {
		s.logger.Error("accept login: generate consent challenge failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}

	cr := &ConsentRequest{
		Challenge:           consentChallenge,
		Subject:             req.Subject,
		ClientID:            lr.ClientID,
		RedirectURI:         lr.RedirectURI,
		Scopes:              lr.Scopes,
		State:               lr.State,
		Nonce:               lr.Nonce,
		CodeChallenge:       lr.CodeChallenge,
		CodeChallengeMethod: lr.CodeChallengeMethod,
		AuthTime:            now,
		ExpiresAt:           now.Add(defaultChallengeTTL),
	}
	if err := s.store.SaveConsentRequest(ctx, cr); err != nil {
		s.logger.Error("accept login: save consent request failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}

	consentURL, err := appendQueryParam(s.consentUIURL(), "consent_challenge", consentChallenge)
	if err != nil {
		s.logger.Error("accept login: build consent redirect failed", zap.Error(err))
		return nil, fmt.Errorf("accept login: %w", api.ErrInternalError)
	}

	s.auditLoginAccept(ctx, req.Subject, lr.ClientID, challenge, false)
	return &api.RedirectResponse{RedirectTo: consentURL}, nil
}

// RejectLogin consumes the login request and redirects to the client's
// redirect_uri with the given error (RFC 6749 §4.1.2.1).
func (s *ConsentService) RejectLogin(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
	lr, err := s.store.ConsumeLoginRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrLoginRequestNotFound) {
			return nil, fmt.Errorf("login request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("reject login: consume login request failed", zap.Error(err))
		return nil, fmt.Errorf("reject login: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventOIDCLoginReject,
		TargetID: lr.ClientID,
		Metadata: map[string]string{
			"challenge_ref": challengeRef(challenge),
			"error":         req.Error,
		},
	})

	return &api.RedirectResponse{RedirectTo: buildRedirectError(lr.RedirectURI, req.Error, req.ErrorDescription, lr.State)}, nil
}

// GetConsentRequest returns details of a pending consent request for
// display by the consent UI.
func (s *ConsentService) GetConsentRequest(ctx context.Context, challenge string) (*api.ConsentRequestInfo, error) {
	cr, err := s.store.GetConsentRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrConsentRequestNotFound) {
			return nil, fmt.Errorf("consent request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("get consent request failed", zap.Error(err))
		return nil, fmt.Errorf("get consent request: %w", api.ErrInternalError)
	}

	return &api.ConsentRequestInfo{
		Challenge:       cr.Challenge,
		ClientID:        cr.ClientID,
		RequestedScopes: cr.Scopes,
		Subject:         cr.Subject,
	}, nil
}

// AcceptConsent consumes the consent request, optionally persists a
// remembered consent grant (req.Remember), and issues an authorization code.
func (s *ConsentService) AcceptConsent(ctx context.Context, challenge string, req *api.AcceptConsentRequest) (*api.RedirectResponse, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	// Validate granted_scopes against the pending request before consuming
	// it, so a malformed accept does not burn the user's consent challenge.
	pending, err := s.store.GetConsentRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrConsentRequestNotFound) {
			return nil, fmt.Errorf("consent request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("accept consent: get consent request failed", zap.Error(err))
		return nil, fmt.Errorf("accept consent: %w", api.ErrInternalError)
	}
	for _, sc := range req.GrantedScopes {
		if !containsScope(pending.Scopes, sc) {
			return nil, fmt.Errorf("granted scope %q was not requested: %w", sc, api.ErrBadRequest)
		}
	}

	cr, err := s.store.ConsumeConsentRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrConsentRequestNotFound) {
			return nil, fmt.Errorf("consent request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("accept consent: consume consent request failed", zap.Error(err))
		return nil, fmt.Errorf("accept consent: %w", api.ErrInternalError)
	}

	if req.Remember {
		clientID, err := uuid.Parse(cr.ClientID)
		if err != nil {
			s.logger.Error("accept consent: invalid client_id in stored consent request", zap.String("client_id", cr.ClientID), zap.Error(err))
			return nil, fmt.Errorf("accept consent: %w", api.ErrInternalError)
		}
		grant := &domain.ConsentGrant{
			ID:        uuid.New(),
			TenantID:  tenantID,
			UserID:    cr.Subject,
			ClientID:  clientID,
			Scopes:    req.GrantedScopes,
			GrantedAt: time.Now().UTC(),
		}
		if _, err := s.grants.Create(ctx, grant); err != nil {
			s.logger.Error("accept consent: save consent grant failed", zap.Error(err))
			return nil, fmt.Errorf("accept consent: %w", api.ErrInternalError)
		}
	}

	redirectTo, err := s.issueCode(ctx, cr.ClientID, cr.RedirectURI, cr.Subject, req.GrantedScopes, cr.Nonce, cr.CodeChallenge, cr.CodeChallengeMethod, cr.State, cr.AuthTime)
	if err != nil {
		return nil, err
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventOIDCConsentGrant,
		ActorID:  cr.Subject,
		TargetID: cr.ClientID,
		Metadata: map[string]string{
			"scopes":   joinScopes(req.GrantedScopes),
			"remember": fmt.Sprintf("%t", req.Remember),
		},
	})

	return &api.RedirectResponse{RedirectTo: redirectTo}, nil
}

// RejectConsent consumes the consent request and redirects to the client's
// redirect_uri with the given error (RFC 6749 §4.1.2.1).
func (s *ConsentService) RejectConsent(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
	cr, err := s.store.ConsumeConsentRequest(ctx, challenge)
	if err != nil {
		if errors.Is(err, ErrConsentRequestNotFound) {
			return nil, fmt.Errorf("consent request %s: %w", challenge, api.ErrNotFound)
		}
		s.logger.Error("reject consent: consume consent request failed", zap.Error(err))
		return nil, fmt.Errorf("reject consent: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventOIDCConsentReject,
		ActorID:  cr.Subject,
		TargetID: cr.ClientID,
		Metadata: map[string]string{
			"challenge_ref": challengeRef(challenge),
			"error":         req.Error,
		},
	})

	return &api.RedirectResponse{RedirectTo: buildRedirectError(cr.RedirectURI, req.Error, req.ErrorDescription, cr.State)}, nil
}

// auditLoginAccept records an accepted login challenge. consentSkipped is
// true when an authorization code was issued directly (first-party client or
// covering remembered grant) rather than redirecting to the consent UI.
func (s *ConsentService) auditLoginAccept(ctx context.Context, subject, clientID, challenge string, consentSkipped bool) {
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventOIDCLoginAccept,
		ActorID:  subject,
		TargetID: clientID,
		Metadata: map[string]string{
			"consent_skipped": fmt.Sprintf("%t", consentSkipped),
			"challenge_ref":   challengeRef(challenge),
		},
	})
}

// challengeRef returns a short correlation reference for a login or consent
// challenge: the first 8 hex chars of its SHA-256. The challenge itself is a
// bearer secret for the accept/reject endpoints and must never be logged.
func challengeRef(challenge string) string {
	sum := sha256.Sum256([]byte(challenge))
	return hex.EncodeToString(sum[:])[:8]
}

// consentUIURL returns the configured consent UI base URL, falling back to
// the login UI URL (config.loadOIDC already defaults ConsentUIURL to
// LoginUIURL when unset, but this guards direct struct construction too,
// e.g. in tests).
func (s *ConsentService) consentUIURL() string {
	if s.cfg.ConsentUIURL != "" {
		return s.cfg.ConsentUIURL
	}
	return s.cfg.LoginUIURL
}

// issueCode generates a one-time authorization code, persists it, and
// returns the redirect URL carrying it back to the client (RFC 6749
// §4.1.2). Shared by the AcceptLogin auto-consent path and AcceptConsent.
func (s *ConsentService) issueCode(ctx context.Context, clientID, redirectURI, subject string, scopes []string, nonce, codeChallenge, codeChallengeMethod, state string, authTime time.Time) (string, error) {
	code, err := generateID(authCodeBytes)
	if err != nil {
		s.logger.Error("issue code: generate code failed", zap.Error(err))
		return "", fmt.Errorf("issue code: %w", api.ErrInternalError)
	}

	ac := &AuthorizationCode{
		Code:                code,
		Subject:             subject,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		Scopes:              scopes,
		Nonce:               nonce,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		AuthTime:            authTime,
		ExpiresAt:           authTime.Add(defaultCodeTTL),
	}
	if err := s.store.SaveAuthorizationCode(ctx, ac); err != nil {
		s.logger.Error("issue code: save authorization code failed", zap.Error(err))
		return "", fmt.Errorf("issue code: %w", api.ErrInternalError)
	}

	return buildRedirectCode(redirectURI, code, state), nil
}
