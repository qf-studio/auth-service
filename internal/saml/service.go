package saml

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Audit event types for SAML operations.
const (
	EventSAMLLoginSuccess = "saml_login_success"
	EventSAMLLoginFailure = "saml_login_failure"
	EventSAMLUserCreated  = "saml_user_created"
	EventSAMLIdentityLinked = "saml_identity_linked"
)

// TokenIssuer abstracts token pair creation for the SAML service.
// This is a narrow interface satisfied by token.Service.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
}

// Service orchestrates the SAML SP authentication flow.
type Service struct {
	sp             SPConfig
	idpConfigs     map[string]IdPConfig
	mappings       map[string]AttributeMapping
	validator      *AssertionValidator
	tracker        *RequestTracker
	provisioner    *Provisioner
	issuer         TokenIssuer
	refreshTokens  storage.RefreshTokenRepository
	audit          audit.EventLogger
	logger         *zap.Logger
}

// NewService creates a new SAML Service with the given configuration.
func NewService(
	sp SPConfig,
	users storage.UserRepository,
	identities storage.SAMLIdentityRepository,
	refreshTokens storage.RefreshTokenRepository,
	issuer TokenIssuer,
	auditor audit.EventLogger,
	logger *zap.Logger,
) *Service {
	tracker := NewRequestTracker(5 * time.Minute)
	validator := NewAssertionValidator(sp.EntityID, sp.ACSURL, tracker)
	provisioner := NewProvisioner(users, identities, logger)

	return &Service{
		sp:            sp,
		idpConfigs:    make(map[string]IdPConfig),
		mappings:      make(map[string]AttributeMapping),
		validator:     validator,
		tracker:       tracker,
		provisioner:   provisioner,
		issuer:        issuer,
		refreshTokens: refreshTokens,
		audit:         auditor,
		logger:        logger,
	}
}

// RegisterIdP registers an Identity Provider with its configuration and attribute mapping.
func (s *Service) RegisterIdP(idp IdPConfig, mapping AttributeMapping) error {
	if idp.EntityID == "" {
		return fmt.Errorf("register idp: entity ID is required")
	}
	if idp.SSOURL == "" {
		return fmt.Errorf("register idp: SSO URL is required")
	}

	if idp.CertificatePEM != "" {
		if err := s.validator.RegisterIdPCertificate(idp.EntityID, idp.CertificatePEM); err != nil {
			return fmt.Errorf("register idp: %w", err)
		}
	}

	s.idpConfigs[idp.EntityID] = idp
	s.mappings[idp.EntityID] = mapping

	s.logger.Info("SAML IdP registered",
		zap.String("entity_id", idp.EntityID),
		zap.String("sso_url", idp.SSOURL),
	)

	return nil
}

// InitiateLogin builds an AuthnRequest for the given IdP and returns the redirect URL.
func (s *Service) InitiateLogin(idpEntityID string) (redirectURL string, err error) {
	idp, ok := s.idpConfigs[idpEntityID]
	if !ok {
		return "", fmt.Errorf("initiate login: %w: %s", domain.ErrSAMLIdPNotConfigured, idpEntityID)
	}

	url, requestID, err := BuildAuthnRequest(s.sp, idp)
	if err != nil {
		return "", fmt.Errorf("initiate login: %w", err)
	}

	s.tracker.Track(requestID)

	s.logger.Debug("SAML AuthnRequest built",
		zap.String("idp", idpEntityID),
		zap.String("request_id", requestID),
	)

	return url, nil
}

// HandleCallback processes a SAML response from the IdP, validates it,
// provisions the user (JIT), and issues a token pair.
func (s *Service) HandleCallback(ctx context.Context, samlResponseB64 string) (*api.AuthResult, error) {
	// Validate and parse the SAML response.
	assertion, err := s.validator.ValidateResponse(samlResponseB64)
	if err != nil {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSAMLLoginFailure,
			Metadata: map[string]string{"error": err.Error()},
		})
		return nil, fmt.Errorf("handle callback: %w", err)
	}

	// Resolve attribute mapping for this IdP.
	mapping, ok := s.mappings[assertion.Issuer]
	if !ok {
		mapping = DefaultAttributeMapping()
	}

	// Map SAML attributes to user fields.
	mapped := mapping.MapAttributes(assertion)

	// JIT provision or match user.
	result, err := s.provisioner.Provision(ctx, assertion, mapped)
	if err != nil {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSAMLLoginFailure,
			Metadata: map[string]string{"error": err.Error(), "idp": assertion.Issuer},
		})
		return nil, fmt.Errorf("handle callback: %w", err)
	}

	// Emit provisioning-specific audit events.
	if result.Created {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSAMLUserCreated,
			ActorID:  result.User.ID,
			TargetID: result.User.ID,
			Metadata: map[string]string{
				"idp":   assertion.Issuer,
				"email": result.User.Email,
			},
		})
	}
	if result.Linked {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     EventSAMLIdentityLinked,
			ActorID:  result.User.ID,
			TargetID: result.User.ID,
			Metadata: map[string]string{
				"idp":   assertion.Issuer,
				"email": result.User.Email,
			},
		})
	}

	// Issue token pair.
	authResult, err := s.issuer.IssueTokenPair(
		ctx,
		result.User.ID,
		result.User.Roles,
		nil,
		domain.ClientTypeUser,
	)
	if err != nil {
		s.logger.Error("failed to issue token pair for SAML login",
			zap.String("user_id", result.User.ID), zap.Error(err))
		return nil, fmt.Errorf("handle callback: issue tokens: %w", err)
	}

	authResult.UserID = result.User.ID

	// Store refresh token signature (best-effort).
	if authResult.RefreshToken != "" {
		if err := s.refreshTokens.Store(ctx, authResult.RefreshToken, result.User.ID, time.Now().Add(24*time.Hour)); err != nil {
			s.logger.Error("failed to store refresh token for SAML login",
				zap.String("user_id", result.User.ID), zap.Error(err))
		}
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventSAMLLoginSuccess,
		ActorID:  result.User.ID,
		TargetID: result.User.ID,
		Metadata: map[string]string{
			"idp":            assertion.Issuer,
			"session_index":  assertion.SessionIndex,
			"jit_provisioned": fmt.Sprintf("%t", result.Created),
		},
	})

	return authResult, nil
}

// GetMetadata returns the SP metadata XML.
func (s *Service) GetMetadata() ([]byte, error) {
	return GenerateMetadata(s.sp)
}

// GetRegisteredIdPs returns the entity IDs of all registered IdPs.
func (s *Service) GetRegisteredIdPs() []string {
	ids := make([]string, 0, len(s.idpConfigs))
	for id := range s.idpConfigs {
		ids = append(ids, id)
	}
	return ids
}
