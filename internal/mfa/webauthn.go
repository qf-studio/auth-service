package mfa

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// WebAuthnSessionStore abstracts challenge session persistence (Redis).
type WebAuthnSessionStore interface {
	StoreWebAuthnSession(ctx context.Context, sessionID string, data []byte) error
	ConsumeWebAuthnSession(ctx context.Context, sessionID string) ([]byte, error)
	PeekMFAToken(ctx context.Context, token string) (string, error)
	ConsumeMFAToken(ctx context.Context, token string) (string, error)
}

// WebAuthnConfig holds relying-party configuration for WebAuthn.
type WebAuthnConfig struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
}

// WebAuthnService implements WebAuthn registration and login ceremonies.
type WebAuthnService struct {
	wa       *webauthn.WebAuthn
	repo     storage.WebAuthnRepository
	sessions WebAuthnSessionStore
	issuer   TokenIssuer
	logger   *zap.Logger
	audit    audit.EventLogger
}

// NewWebAuthnService creates a new WebAuthn service.
func NewWebAuthnService(
	cfg WebAuthnConfig,
	repo storage.WebAuthnRepository,
	sessions WebAuthnSessionStore,
	issuer TokenIssuer,
	logger *zap.Logger,
	auditor audit.EventLogger,
) (*WebAuthnService, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("create webauthn instance: %w", err)
	}
	return &WebAuthnService{
		wa:       wa,
		repo:     repo,
		sessions: sessions,
		issuer:   issuer,
		logger:   logger,
		audit:    auditor,
	}, nil
}

// webauthnUser adapts our user identity to the webauthn.User interface.
type webauthnUser struct {
	id          []byte
	name        string
	displayName string
	credentials []webauthn.Credential
}

func (u *webauthnUser) WebAuthnID() []byte                         { return u.id }
func (u *webauthnUser) WebAuthnName() string                       { return u.name }
func (u *webauthnUser) WebAuthnDisplayName() string                { return u.displayName }
func (u *webauthnUser) WebAuthnCredentials() []webauthn.Credential { return u.credentials }

// toLibCredential converts a domain credential to the library's Credential type.
func toLibCredential(c *domain.WebAuthnCredential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, len(c.Transports))
	for i, t := range c.Transports {
		transports[i] = protocol.AuthenticatorTransport(t)
	}
	return webauthn.Credential{
		ID:              c.CredentialID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

// buildUser creates a webauthnUser from the user identity and their stored credentials.
func (s *WebAuthnService) buildUser(ctx context.Context, userID, email string) (*webauthnUser, error) {
	creds, err := s.repo.GetCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}
	libCreds := make([]webauthn.Credential, len(creds))
	for i := range creds {
		libCreds[i] = toLibCredential(&creds[i])
	}
	return &webauthnUser{
		id:          []byte(userID),
		name:        email,
		displayName: email,
		credentials: libCreds,
	}, nil
}

// sessionKey returns the Redis session key for a given flow and user.
func sessionKey(flow, userID string) string {
	return flow + ":" + userID
}

// BeginRegistration starts the WebAuthn registration ceremony.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, userID, email string) (interface{}, error) {
	user, err := s.buildUser(ctx, userID, email)
	if err != nil {
		return nil, err
	}

	// Exclude already-registered credentials to prevent re-registration.
	excludeList := make([]protocol.CredentialDescriptor, len(user.credentials))
	for i, c := range user.credentials {
		excludeList[i] = c.Descriptor()
	}

	creation, session, err := s.wa.BeginRegistration(user,
		webauthn.WithExclusions(excludeList),
	)
	if err != nil {
		return nil, fmt.Errorf("begin registration: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}
	if err := s.sessions.StoreWebAuthnSession(ctx, sessionKey("reg", userID), sessionBytes); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}

	return creation, nil
}

// FinishRegistration completes the WebAuthn registration ceremony and stores the credential.
func (s *WebAuthnService) FinishRegistration(ctx context.Context, userID, email string, body []byte) error {
	user, err := s.buildUser(ctx, userID, email)
	if err != nil {
		return err
	}

	sessionBytes, err := s.sessions.ConsumeWebAuthnSession(ctx, sessionKey("reg", userID))
	if err != nil {
		return fmt.Errorf("session not found or expired: %w", api.ErrUnauthorized)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialCreationResponseBody(bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("invalid credential response: %w", api.ErrUnauthorized)
	}

	credential, err := s.wa.CreateCredential(user, session, parsedResponse)
	if err != nil {
		return fmt.Errorf("create credential: %w", api.ErrUnauthorized)
	}

	transports := make([]string, len(credential.Transport))
	for i, t := range credential.Transport {
		transports[i] = string(t)
	}

	domainCred := &domain.WebAuthnCredential{
		ID:              uuid.New().String(),
		UserID:          userID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		Transports:      transports,
		Name:            "Security Key",
		CreatedAt:       time.Now().UTC(),
	}

	if err := s.repo.CreateCredential(ctx, domainCred); err != nil {
		return fmt.Errorf("save credential: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "webauthn_credential_registered",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// BeginLogin starts the WebAuthn login ceremony.
// The mfaToken is used to identify the user (peeked, not consumed).
func (s *WebAuthnService) BeginLogin(ctx context.Context, mfaToken string) (interface{}, error) {
	userID, err := s.sessions.PeekMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired mfa token: %w", api.ErrUnauthorized)
	}

	user, err := s.buildUser(ctx, userID, "")
	if err != nil {
		return nil, err
	}

	if len(user.credentials) == 0 {
		return nil, fmt.Errorf("no webauthn credentials registered: %w", api.ErrNotFound)
	}

	assertion, session, err := s.wa.BeginLogin(user)
	if err != nil {
		return nil, fmt.Errorf("begin login: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}
	if err := s.sessions.StoreWebAuthnSession(ctx, sessionKey("login", userID), sessionBytes); err != nil {
		return nil, fmt.Errorf("store session: %w", err)
	}

	return assertion, nil
}

// FinishLogin completes the WebAuthn login ceremony, consuming the MFA token and issuing tokens.
func (s *WebAuthnService) FinishLogin(ctx context.Context, mfaToken string, body []byte) (*api.AuthResult, error) {
	// Consume the MFA token atomically — prevents reuse.
	userID, err := s.sessions.ConsumeMFAToken(ctx, mfaToken)
	if err != nil {
		return nil, fmt.Errorf("invalid or expired mfa token: %w", api.ErrUnauthorized)
	}

	user, err := s.buildUser(ctx, userID, "")
	if err != nil {
		return nil, err
	}

	sessionBytes, err := s.sessions.ConsumeWebAuthnSession(ctx, sessionKey("login", userID))
	if err != nil {
		return nil, fmt.Errorf("session not found or expired: %w", api.ErrUnauthorized)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	parsedResponse, err := protocol.ParseCredentialRequestResponseBody(bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("invalid assertion response: %w", api.ErrUnauthorized)
	}

	credential, err := s.wa.ValidateLogin(user, session, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("validate login: %w", api.ErrUnauthorized)
	}

	// Update sign count for clone detection.
	if err := s.repo.UpdateSignCount(ctx, credential.ID, credential.Authenticator.SignCount); err != nil {
		s.logger.Error("failed to update webauthn sign count", zap.Error(err))
	}

	// Issue token pair.
	result, err := s.issuer.IssueTokenPair(ctx, userID, nil, nil, domain.ClientTypeUser)
	if err != nil {
		return nil, fmt.Errorf("issue tokens after webauthn: %w", err)
	}
	result.UserID = userID

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "webauthn_login_success",
		ActorID:  userID,
		TargetID: userID,
	})

	return result, nil
}

// ListCredentials returns all active WebAuthn credentials for a user.
func (s *WebAuthnService) ListCredentials(ctx context.Context, userID string) ([]api.WebAuthnCredentialInfo, error) {
	creds, err := s.repo.GetCredentialsByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list credentials: %w", err)
	}
	infos := make([]api.WebAuthnCredentialInfo, len(creds))
	for i, c := range creds {
		infos[i] = api.WebAuthnCredentialInfo{
			ID:         c.ID,
			Name:       c.Name,
			CreatedAt:  c.CreatedAt,
			LastUsedAt: c.LastUsedAt,
		}
	}
	return infos, nil
}

// DeleteCredential soft-deletes a WebAuthn credential.
func (s *WebAuthnService) DeleteCredential(ctx context.Context, userID, credentialID string) error {
	if err := s.repo.DeleteCredential(ctx, userID, credentialID); err != nil {
		if err == storage.ErrNotFound {
			return fmt.Errorf("credential not found: %w", api.ErrNotFound)
		}
		return fmt.Errorf("delete credential: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "webauthn_credential_deleted",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}
