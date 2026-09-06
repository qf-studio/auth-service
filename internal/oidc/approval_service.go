package oidc

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// clientSecretPrefix is prepended to generated client secrets for leak
	// detection, mirroring admin.ClientService.
	clientSecretPrefix = "qf_cs_"
	// clientSecretBytes is the number of random bytes for client secret generation.
	clientSecretBytes = 32
)

// ApprovalService implements api.AdminClientApprovalService: the third-party
// OAuth2 client creation and admin-approval workflow. Third-party clients
// are created in domain.ClientStatusSuspended and cannot be used to
// authorize until ApproveClient activates them.
type ApprovalService struct {
	repo   storage.ClientRepository
	hasher password.Hasher
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewApprovalService creates a new ApprovalService.
func NewApprovalService(repo storage.ClientRepository, hasher password.Hasher, logger *zap.Logger, auditor audit.EventLogger) *ApprovalService {
	return &ApprovalService{
		repo:   repo,
		hasher: hasher,
		logger: logger,
		audit:  auditor,
	}
}

// Compile-time assertion that ApprovalService satisfies api.AdminClientApprovalService.
var _ api.AdminClientApprovalService = (*ApprovalService)(nil)

// CreateThirdPartyClient creates a new OAuth2 client requiring admin
// approval before use. Mirrors admin.ClientService.CreateClient, but stamps
// Owner: thirdPartyOwner (see deps.go) and starts the client in
// domain.ClientStatusSuspended rather than active.
func (s *ApprovalService) CreateThirdPartyClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	tenantID := domain.TenantIDFromContext(ctx)
	clientType := domain.ClientType(req.ClientType)
	isPublic := clientType == domain.ClientTypePublic

	var secret, hash string
	if !isPublic {
		var err error
		secret, err = generateClientSecret()
		if err != nil {
			s.logger.Error("generate client secret failed", zap.Error(err))
			return nil, fmt.Errorf("create third-party client: %w", api.ErrInternalError)
		}

		hash, err = s.hasher.Hash(secret)
		if err != nil {
			s.logger.Error("hash client secret failed", zap.Error(err))
			return nil, fmt.Errorf("create third-party client: %w", api.ErrInternalError)
		}
	}

	now := time.Now().UTC()
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}
	redirectURIs := req.RedirectURIs
	if redirectURIs == nil {
		redirectURIs = []string{}
	}
	audience := req.Audience
	if audience == nil {
		audience = []string{}
	}

	client := &domain.Client{
		ID:             uuid.New(),
		TenantID:       tenantID,
		Name:           req.Name,
		ClientType:     clientType,
		SecretHash:     hash,
		Scopes:         scopes,
		RedirectURIs:   redirectURIs,
		Audience:       audience,
		Owner:          thirdPartyOwner,
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusSuspended,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	created, err := s.repo.Create(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateClient) {
			return nil, fmt.Errorf("client name exists: %w", api.ErrConflict)
		}
		s.logger.Error("create third-party client failed", zap.Error(err))
		return nil, fmt.Errorf("create third-party client: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminClientCreate,
		TargetID: created.ID.String(),
		Metadata: map[string]string{"name": created.Name, "type": string(created.ClientType), "owner": thirdPartyOwner},
	})

	return &api.AdminClientWithSecret{
		AdminClient:  domainClientToAdmin(created),
		ClientSecret: secret,
	}, nil
}

// ApproveClient activates a suspended third-party client, enabling it for
// use. No-op-safe if already active; rejected with api.ErrNotFound if the
// client is revoked (see storage.ClientRepository.Activate).
func (s *ApprovalService) ApproveClient(ctx context.Context, clientID string) (*api.ClientApprovalInfo, error) {
	tenantID := domain.TenantIDFromContext(ctx)
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	existing, err := s.repo.FindByID(ctx, tenantID, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("approve client: find client failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("approve client: %w", api.ErrInternalError)
	}

	if err := s.repo.Activate(ctx, tenantID, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("approve client: activate failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("approve client: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminClientApprove,
		TargetID: clientID,
	})

	// ApprovedBy is intentionally left empty: this codebase has no
	// admin-actor-context propagation mechanism (see other admin services,
	// which likewise leave audit.Event.ActorID blank for admin operations).
	return &api.ClientApprovalInfo{
		ClientID:   clientID,
		ClientName: existing.Name,
		Approved:   true,
		ApprovedAt: &now,
	}, nil
}

// generateClientSecret generates a cryptographically random client secret,
// mirroring admin.ClientService.generateClientSecret (unexported there, so
// duplicated here rather than imported).
func generateClientSecret() (string, error) {
	b := make([]byte, clientSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return clientSecretPrefix + hex.EncodeToString(b), nil
}

// domainClientToAdmin converts a domain.Client to an api.AdminClient
// response DTO, mirroring admin.ClientService.domainClientToAdmin
// (unexported there, so duplicated here rather than imported).
func domainClientToAdmin(c *domain.Client) api.AdminClient {
	return api.AdminClient{
		ID:           c.ID.String(),
		Name:         c.Name,
		ClientType:   string(c.ClientType),
		Scopes:       c.Scopes,
		RedirectURIs: c.RedirectURIs,
		Audience:     c.Audience,
		CreatedAt:    c.CreatedAt,
		UpdatedAt:    c.UpdatedAt,
	}
}
