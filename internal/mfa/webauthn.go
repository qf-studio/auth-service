package mfa

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	sessionPurposeRegistration = "registration"
	sessionPurposeLogin        = "login"
)

// WebAuthnSessionStore abstracts temporary WebAuthn session storage (Redis).
type WebAuthnSessionStore interface {
	StoreWebAuthnSession(ctx context.Context, userID, purpose string, data []byte) error
	ConsumeWebAuthnSession(ctx context.Context, userID, purpose string) ([]byte, error)
}

// WebAuthnProvider abstracts the go-webauthn library for testability.
type WebAuthnProvider interface {
	BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	CreateCredential(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error)
	BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	ValidateLogin(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error)
}

// webauthnProviderAdapter wraps *webauthn.WebAuthn to satisfy WebAuthnProvider.
type webauthnProviderAdapter struct {
	wa *webauthn.WebAuthn
}

func (a *webauthnProviderAdapter) BeginRegistration(user webauthn.User, opts ...webauthn.RegistrationOption) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	return a.wa.BeginRegistration(user, opts...)
}

func (a *webauthnProviderAdapter) CreateCredential(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*webauthn.Credential, error) {
	return a.wa.CreateCredential(user, session, parsedResponse)
}

func (a *webauthnProviderAdapter) BeginLogin(user webauthn.User, opts ...webauthn.LoginOption) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	return a.wa.BeginLogin(user, opts...)
}

func (a *webauthnProviderAdapter) ValidateLogin(user webauthn.User, session webauthn.SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*webauthn.Credential, error) {
	return a.wa.ValidateLogin(user, session, parsedResponse)
}

// WebAuthnConfig holds WebAuthn relying-party settings.
type WebAuthnConfig struct {
	RPDisplayName string   // Human-readable RP name
	RPID          string   // RP domain (e.g. "example.com")
	RPOrigins     []string // Allowed origins (e.g. "https://example.com")
}

// webauthnUser adapts a domain.User + stored WebAuthn credentials to the webauthn.User interface.
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

// toLibCredentials converts domain credentials to webauthn library credentials.
func toLibCredentials(creds []domain.WebAuthnCredential) []webauthn.Credential {
	out := make([]webauthn.Credential, len(creds))
	for i, c := range creds {
		out[i] = webauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return out
}

// WebAuthnService implements WebAuthn registration and authentication flows.
type WebAuthnService struct {
	provider WebAuthnProvider
	creds    storage.WebAuthnCredentialRepository
	sessions WebAuthnSessionStore
	logger   *zap.Logger
	audit    audit.EventLogger
}

// NewWebAuthnService creates a new WebAuthn service with the configured relying party.
func NewWebAuthnService(
	cfg WebAuthnConfig,
	creds storage.WebAuthnCredentialRepository,
	sessions WebAuthnSessionStore,
	logger *zap.Logger,
	auditor audit.EventLogger,
) (*WebAuthnService, error) {
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: cfg.RPDisplayName,
		RPID:          cfg.RPID,
		RPOrigins:     cfg.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("configure webauthn relying party: %w", err)
	}

	return &WebAuthnService{
		provider: &webauthnProviderAdapter{wa: wa},
		creds:    creds,
		sessions: sessions,
		logger:   logger,
		audit:    auditor,
	}, nil
}

// newWebAuthnServiceWithProvider creates a WebAuthnService with an injected provider (for testing).
func newWebAuthnServiceWithProvider(
	provider WebAuthnProvider,
	creds storage.WebAuthnCredentialRepository,
	sessions WebAuthnSessionStore,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *WebAuthnService {
	return &WebAuthnService{
		provider: provider,
		creds:    creds,
		sessions: sessions,
		logger:   logger,
		audit:    auditor,
	}
}

// BeginRegistration starts a WebAuthn credential registration ceremony.
// Returns the credential creation options to send to the client and stores the session server-side.
func (s *WebAuthnService) BeginRegistration(ctx context.Context, user *domain.User) (*protocol.CredentialCreation, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	existing, err := s.creds.GetCredentialsByUser(ctx, tenantID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get existing credentials: %w", err)
	}

	waUser := &webauthnUser{
		id:          []byte(user.ID),
		name:        user.Email,
		displayName: user.Name,
		credentials: toLibCredentials(existing),
	}

	// Exclude already-registered credentials so the authenticator generates a new one.
	excludeList := make([]protocol.CredentialDescriptor, len(existing))
	for i, c := range existing {
		excludeList[i] = protocol.CredentialDescriptor{
			Type:         protocol.PublicKeyCredentialType,
			CredentialID: c.CredentialID,
		}
	}

	creation, session, err := s.provider.BeginRegistration(waUser, webauthn.WithExclusions(excludeList))
	if err != nil {
		return nil, fmt.Errorf("begin webauthn registration: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal registration session: %w", err)
	}

	if err := s.sessions.StoreWebAuthnSession(ctx, user.ID, sessionPurposeRegistration, sessionBytes); err != nil {
		return nil, fmt.Errorf("store registration session: %w", err)
	}

	return creation, nil
}

// FinishRegistration completes the WebAuthn registration ceremony by verifying the authenticator response.
// The credentialName is a user-friendly label for the credential.
func (s *WebAuthnService) FinishRegistration(
	ctx context.Context,
	user *domain.User,
	credentialName string,
	parsedResponse *protocol.ParsedCredentialCreationData,
) (*domain.WebAuthnCredential, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	sessionBytes, err := s.sessions.ConsumeWebAuthnSession(ctx, user.ID, sessionPurposeRegistration)
	if err != nil {
		return nil, fmt.Errorf("consume registration session: %w", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return nil, fmt.Errorf("unmarshal registration session: %w", err)
	}

	existing, err := s.creds.GetCredentialsByUser(ctx, tenantID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get existing credentials: %w", err)
	}

	waUser := &webauthnUser{
		id:          []byte(user.ID),
		name:        user.Email,
		displayName: user.Name,
		credentials: toLibCredentials(existing),
	}

	credential, err := s.provider.CreateCredential(waUser, session, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("verify registration response: %w", err)
	}

	now := time.Now().UTC()
	domainCred := &domain.WebAuthnCredential{
		ID:              uuid.New().String(),
		TenantID:        tenantID,
		UserID:          user.ID,
		CredentialID:    credential.ID,
		PublicKey:       credential.PublicKey,
		AttestationType: credential.AttestationType,
		AAGUID:          credential.Authenticator.AAGUID,
		SignCount:       credential.Authenticator.SignCount,
		CloneWarning:    false,
		Name:            credentialName,
		CreatedAt:       now,
	}

	if err := s.creds.CreateCredential(ctx, domainCred); err != nil {
		return nil, fmt.Errorf("store credential: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "webauthn_credential_registered",
		ActorID:  user.ID,
		TargetID: user.ID,
	})

	return domainCred, nil
}

// BeginLogin starts a WebAuthn authentication ceremony.
// Returns the credential assertion options to send to the client and stores the session server-side.
func (s *WebAuthnService) BeginLogin(ctx context.Context, user *domain.User) (*protocol.CredentialAssertion, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	existing, err := s.creds.GetCredentialsByUser(ctx, tenantID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	if len(existing) == 0 {
		return nil, fmt.Errorf("no webauthn credentials registered: %w", storage.ErrNotFound)
	}

	waUser := &webauthnUser{
		id:          []byte(user.ID),
		name:        user.Email,
		displayName: user.Name,
		credentials: toLibCredentials(existing),
	}

	assertion, session, err := s.provider.BeginLogin(waUser)
	if err != nil {
		return nil, fmt.Errorf("begin webauthn login: %w", err)
	}

	sessionBytes, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal login session: %w", err)
	}

	if err := s.sessions.StoreWebAuthnSession(ctx, user.ID, sessionPurposeLogin, sessionBytes); err != nil {
		return nil, fmt.Errorf("store login session: %w", err)
	}

	return assertion, nil
}

// FinishLogin completes the WebAuthn authentication ceremony by verifying the authenticator assertion.
// It updates the credential's sign count and sets the clone warning flag if a regression is detected.
func (s *WebAuthnService) FinishLogin(
	ctx context.Context,
	user *domain.User,
	parsedResponse *protocol.ParsedCredentialAssertionData,
) (*domain.WebAuthnCredential, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	sessionBytes, err := s.sessions.ConsumeWebAuthnSession(ctx, user.ID, sessionPurposeLogin)
	if err != nil {
		return nil, fmt.Errorf("consume login session: %w", err)
	}

	var session webauthn.SessionData
	if err := json.Unmarshal(sessionBytes, &session); err != nil {
		return nil, fmt.Errorf("unmarshal login session: %w", err)
	}

	existing, err := s.creds.GetCredentialsByUser(ctx, tenantID, user.ID)
	if err != nil {
		return nil, fmt.Errorf("get credentials: %w", err)
	}

	waUser := &webauthnUser{
		id:          []byte(user.ID),
		name:        user.Email,
		displayName: user.Name,
		credentials: toLibCredentials(existing),
	}

	credential, err := s.provider.ValidateLogin(waUser, session, parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("verify login response: %w", err)
	}

	// Update sign count and clone warning in storage.
	if err := s.creds.UpdateSignCount(ctx, tenantID, credential.ID, credential.Authenticator.SignCount, credential.Authenticator.CloneWarning); err != nil {
		s.logger.Error("failed to update sign count",
			zap.Error(err),
			zap.String("user_id", user.ID),
		)
	}

	// Find the matching domain credential to return.
	for i := range existing {
		if byteSliceEqual(existing[i].CredentialID, credential.ID) {
			existing[i].SignCount = credential.Authenticator.SignCount
			existing[i].CloneWarning = credential.Authenticator.CloneWarning

			s.audit.LogEvent(ctx, audit.Event{
				Type:     "webauthn_login_success",
				ActorID:  user.ID,
				TargetID: user.ID,
			})

			return &existing[i], nil
		}
	}

	// Should not happen — ValidateLogin already matched the credential.
	return nil, fmt.Errorf("credential not found after validation")
}

func byteSliceEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
