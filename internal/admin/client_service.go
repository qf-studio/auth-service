package admin

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
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// clientSecretPrefix is prepended to generated client secrets for leak detection.
	clientSecretPrefix = "qf_cs_"
	// clientSecretBytes is the number of random bytes for client secret generation.
	clientSecretBytes = 32
	// gracePeriodDuration is the grace period after secret rotation.
	gracePeriodDuration = 24 * time.Hour
)

// ClientService implements api.AdminClientService.
type ClientService struct {
	repo   storage.ClientRepository
	hasher password.Hasher
	logger *zap.Logger
}

// NewClientService creates a new admin client service.
func NewClientService(repo storage.ClientRepository, hasher password.Hasher, logger *zap.Logger) *ClientService {
	return &ClientService{
		repo:   repo,
		hasher: hasher,
		logger: logger,
	}
}

// ListClients returns a paginated list of OAuth2 clients.
func (s *ClientService) ListClients(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error) {
	offset := (page - 1) * perPage

	clients, total, err := s.repo.List(ctx, perPage, offset, includeDeleted)
	if err != nil {
		s.logger.Error("list clients failed", zap.Error(err))
		return nil, fmt.Errorf("list clients: %w", api.ErrInternalError)
	}

	result := &api.AdminClientList{
		Clients: make([]api.AdminClient, 0, len(clients)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	for _, c := range clients {
		result.Clients = append(result.Clients, domainClientToAdmin(c))
	}

	return result, nil
}

// GetClient retrieves a single client by ID.
func (s *ClientService) GetClient(ctx context.Context, clientID string) (*api.AdminClient, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	c, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("get client failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("get client: %w", api.ErrInternalError)
	}

	admin := domainClientToAdmin(c)
	return &admin, nil
}

// CreateClient creates a new OAuth2 client with a generated secret.
func (s *ClientService) CreateClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	secret, err := generateClientSecret()
	if err != nil {
		s.logger.Error("generate client secret failed", zap.Error(err))
		return nil, fmt.Errorf("create client: %w", api.ErrInternalError)
	}

	hash, err := s.hasher.Hash(secret)
	if err != nil {
		s.logger.Error("hash client secret failed", zap.Error(err))
		return nil, fmt.Errorf("create client: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	client := &domain.Client{
		ID:             uuid.New(),
		Name:           req.Name,
		ClientType:     domain.ClientType(req.ClientType),
		SecretHash:     hash,
		Scopes:         scopes,
		Owner:          "admin",
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	created, err := s.repo.Create(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateClient) {
			return nil, fmt.Errorf("client name exists: %w", api.ErrConflict)
		}
		s.logger.Error("create client failed", zap.Error(err))
		return nil, fmt.Errorf("create client: %w", api.ErrInternalError)
	}

	return &api.AdminClientWithSecret{
		AdminClient:  domainClientToAdmin(created),
		ClientSecret: secret,
	}, nil
}

// UpdateClient modifies client fields.
func (s *ClientService) UpdateClient(ctx context.Context, clientID string, req *api.UpdateClientRequest) (*api.AdminClient, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("find client for update failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("update client: %w", api.ErrInternalError)
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrDuplicateClient) {
			return nil, fmt.Errorf("client name exists: %w", api.ErrConflict)
		}
		s.logger.Error("update client failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("update client: %w", api.ErrInternalError)
	}

	admin := domainClientToAdmin(updated)
	return &admin, nil
}

// DeleteClient performs a soft delete (sets status to revoked).
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	err = s.repo.SoftDelete(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrAlreadyDeleted) {
			return fmt.Errorf("client %s already deleted: %w", clientID, api.ErrConflict)
		}
		s.logger.Error("delete client failed", zap.String("client_id", clientID), zap.Error(err))
		return fmt.Errorf("delete client: %w", api.ErrInternalError)
	}
	return nil
}

// RotateSecret generates a new secret for the client with a grace period.
func (s *ClientService) RotateSecret(ctx context.Context, clientID string) (*api.AdminClientWithSecret, error) {
	id, err := uuid.Parse(clientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	secret, err := generateClientSecret()
	if err != nil {
		s.logger.Error("generate client secret failed", zap.Error(err))
		return nil, fmt.Errorf("rotate secret: %w", api.ErrInternalError)
	}

	hash, err := s.hasher.Hash(secret)
	if err != nil {
		s.logger.Error("hash client secret failed", zap.Error(err))
		return nil, fmt.Errorf("rotate secret: %w", api.ErrInternalError)
	}

	graceEnd := time.Now().UTC().Add(gracePeriodDuration)

	if err := s.repo.RotateSecret(ctx, id, hash, graceEnd); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("rotate secret failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("rotate secret: %w", api.ErrInternalError)
	}

	// Re-read the client to get the updated record.
	client, err := s.repo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("re-read client after rotation failed", zap.String("client_id", clientID), zap.Error(err))
		return nil, fmt.Errorf("rotate secret: %w", api.ErrInternalError)
	}
	return &api.AdminClientWithSecret{
		AdminClient:     domainClientToAdmin(client),
		ClientSecret:    secret,
		GracePeriodEnds: &graceEnd,
	}, nil
}

// generateClientSecret generates a cryptographically random client secret.
func generateClientSecret() (string, error) {
	b := make([]byte, clientSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return clientSecretPrefix + hex.EncodeToString(b), nil
}

// domainClientToAdmin converts a domain.Client to an api.AdminClient response DTO.
func domainClientToAdmin(c *domain.Client) api.AdminClient {
	return api.AdminClient{
		ID:         c.ID.String(),
		Name:       c.Name,
		ClientType: string(c.ClientType),
		Scopes:     c.Scopes,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}
