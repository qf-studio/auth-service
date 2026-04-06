package broker

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	// DefaultProxyTokenTTL is the lifetime of brokered proxy tokens.
	DefaultProxyTokenTTL = 5 * time.Minute

	// rbacAction is the RBAC action string used for broker authorization checks.
	rbacAction = "broker:access"
)

// CredentialStore abstracts storage of encrypted agent credentials.
// Satisfied by the credential repository in internal/storage.
type CredentialStore interface {
	GetCredential(ctx context.Context, credentialID string) (*domain.AgentCredential, error)
}

// ProxyIssuer abstracts short-lived proxy token issuance.
// Satisfied by token.Service.IssueProxyToken.
type ProxyIssuer interface {
	IssueProxyToken(ctx context.Context, subject string, audience string, scopes []string, ttl time.Duration) (string, error)
}

// AccessChecker abstracts RBAC permission checks.
// Satisfied by rbac.Service.CheckPermission.
type AccessChecker interface {
	CheckPermission(ctx context.Context, sub, obj, act string) (bool, error)
}

// BrokerResult is returned on successful credential brokering.
type BrokerResult struct {
	ProxyToken    string    `json:"proxy_token"`
	TargetService string    `json:"target_service"`
	ExpiresAt     time.Time `json:"expires_at"`
	TokenType     string    `json:"token_type"`
}

// Service is the credential broker. It validates agent identity, checks
// authorization, decrypts credentials from the vault, issues short-lived
// proxy tokens, and records brokered access via the audit logger.
type Service struct {
	store   CredentialStore
	issuer  ProxyIssuer
	checker AccessChecker
	vault   *Vault
	logger  *zap.Logger
	audit   audit.EventLogger
}

// NewService creates a new broker Service.
func NewService(
	store CredentialStore,
	issuer ProxyIssuer,
	checker AccessChecker,
	vault *Vault,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		store:   store,
		issuer:  issuer,
		checker: checker,
		vault:   vault,
		logger:  logger,
		audit:   auditor,
	}
}

// BrokerAccess validates the requesting agent, checks authorization for the
// target credential, decrypts it, issues a short-lived proxy token scoped to
// the credential's target service, and records the brokered access event.
//
// The agent never receives the real credential — only a proxy token.
func (s *Service) BrokerAccess(ctx context.Context, agentClientID string, credentialID string) (*BrokerResult, error) {
	// 1. Fetch the credential from storage.
	cred, err := s.store.GetCredential(ctx, credentialID)
	if err != nil {
		return nil, fmt.Errorf("broker: fetch credential: %w", err)
	}
	if cred == nil {
		return nil, domain.ErrCredentialNotFound
	}

	// 2. Verify the credential is active and not expired.
	if !cred.IsActive() {
		s.logDenied(ctx, agentClientID, credentialID, "credential_inactive")
		if cred.Status == domain.CredentialStatusRevoked {
			return nil, domain.ErrCredentialRevoked
		}
		return nil, domain.ErrCredentialExpired
	}

	// 3. Verify the requesting agent owns this credential.
	if cred.AgentClientID.String() != agentClientID {
		s.logDenied(ctx, agentClientID, credentialID, "not_owner")
		return nil, domain.ErrBrokerAccessDenied
	}

	// 4. Check RBAC: does the agent have broker:access on this credential?
	allowed, err := s.checker.CheckPermission(ctx, agentClientID, credentialID, rbacAction)
	if err != nil {
		return nil, fmt.Errorf("broker: check permission: %w", err)
	}
	if !allowed {
		s.logDenied(ctx, agentClientID, credentialID, "rbac_denied")
		return nil, domain.ErrBrokerAccessDenied
	}

	// 5. Decrypt the credential payload to verify vault integrity.
	//    The decrypted payload is NOT returned to the agent — it's only used
	//    to confirm the credential is still decryptable before issuing a proxy token.
	_, err = s.vault.Decrypt(cred.EncryptedPayload)
	if err != nil {
		s.logger.Error("broker: vault decryption failed",
			zap.String("credential_id", credentialID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("broker: %w", domain.ErrDecryptionFailed)
	}

	// 6. Issue a short-lived proxy token scoped to the target service.
	expiresAt := time.Now().Add(DefaultProxyTokenTTL)
	proxyToken, err := s.issuer.IssueProxyToken(
		ctx,
		agentClientID,
		cred.TargetService,
		cred.Scopes,
		DefaultProxyTokenTTL,
	)
	if err != nil {
		return nil, fmt.Errorf("broker: issue proxy token: %w", err)
	}

	// 7. Record the brokered access event.
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventBrokerAccess,
		ActorID:  agentClientID,
		TargetID: credentialID,
		Metadata: map[string]string{
			"target_service":  cred.TargetService,
			"credential_type": cred.CredentialType,
		},
	})

	s.logger.Info("broker: proxy token issued",
		zap.String("agent_client_id", agentClientID),
		zap.String("credential_id", credentialID),
		zap.String("target_service", cred.TargetService),
	)

	return &BrokerResult{
		ProxyToken:    proxyToken,
		TargetService: cred.TargetService,
		ExpiresAt:     expiresAt,
		TokenType:     "Bearer",
	}, nil
}

// logDenied records an access-denied audit event with a reason.
func (s *Service) logDenied(ctx context.Context, agentClientID, credentialID, reason string) {
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventBrokerAccessDenied,
		ActorID:  agentClientID,
		TargetID: credentialID,
		Metadata: map[string]string{"reason": reason},
	})
	s.logger.Warn("broker: access denied",
		zap.String("agent_client_id", agentClientID),
		zap.String("credential_id", credentialID),
		zap.String("reason", reason),
	)
}
