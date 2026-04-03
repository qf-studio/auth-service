package admin

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// clientSecretPrefix is prepended to client secrets for leak detection.
	clientSecretPrefix = "qf_cs_"

	// clientSecretBytes is the number of random bytes in a generated client secret.
	clientSecretBytes = 32

	// defaultAccessTokenTTL is the default access token TTL for new clients (1 hour).
	defaultAccessTokenTTL = 3600

	// secretRotationGracePeriod is how long the previous secret remains in the grace window.
	// Note: actual dual-secret validation is a Phase 2 concern; here we communicate the boundary.
	secretRotationGracePeriod = 24 * time.Hour
)

// ClientService implements api.AdminClientService for admin OAuth2 client management.
type ClientService struct {
	repo   ClientRepository
	hasher password.Hasher
}

// NewClientService creates a new admin ClientService.
func NewClientService(repo ClientRepository, hasher password.Hasher) *ClientService {
	return &ClientService{repo: repo, hasher: hasher}
}

// ListClients returns a paginated list of OAuth2 clients.
func (s *ClientService) ListClients(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error) {
	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}

	offset := (page - 1) * perPage

	clients, total, err := s.repo.FindAll(ctx, offset, perPage, includeDeleted)
	if err != nil {
		return nil, fmt.Errorf("list clients: %w", err)
	}

	result := make([]api.AdminClient, len(clients))
	for i, c := range clients {
		result[i] = domainClientToAdminClient(c)
	}

	return &api.AdminClientList{
		Clients: result,
		Total:   int(total),
		Page:    page,
		PerPage: perPage,
	}, nil
}

// GetClient returns a single OAuth2 client by ID.
func (s *ClientService) GetClient(ctx context.Context, clientID string) (*api.AdminClient, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get client: %w", err)
	}

	result := domainClientToAdminClient(client)
	return &result, nil
}

// CreateClient registers a new OAuth2 client, generates a secret, and returns it once.
func (s *ClientService) CreateClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	rawSecret, err := generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client secret: %w", err)
	}

	secretHash, err := s.hasher.Hash(rawSecret)
	if err != nil {
		return nil, fmt.Errorf("hash client secret: %w", err)
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:             uuid.New(),
		Name:           req.Name,
		ClientType:     domain.ClientType(req.ClientType),
		SecretHash:     secretHash,
		Scopes:         req.Scopes,
		Status:         domain.ClientStatusActive,
		AccessTokenTTL: defaultAccessTokenTTL,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	created, err := s.repo.Create(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateEmail) {
			return nil, fmt.Errorf("client name %q already exists: %w", req.Name, api.ErrConflict)
		}
		return nil, fmt.Errorf("create client: %w", err)
	}

	return &api.AdminClientWithSecret{
		AdminClient:  domainClientToAdminClient(created),
		ClientSecret: rawSecret,
	}, nil
}

// UpdateClient applies partial field updates to an existing OAuth2 client.
func (s *ClientService) UpdateClient(ctx context.Context, clientID string, req *api.UpdateClientRequest) (*api.AdminClient, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get client for update: %w", err)
	}

	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}
	client.UpdatedAt = time.Now().UTC()

	updated, err := s.repo.Update(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("update client: %w", err)
	}

	result := domainClientToAdminClient(updated)
	return &result, nil
}

// DeleteClient revokes (soft-deletes) an OAuth2 client.
func (s *ClientService) DeleteClient(ctx context.Context, clientID string) error {
	if err := s.repo.Revoke(ctx, clientID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return fmt.Errorf("delete client: %w", err)
	}
	return nil
}

// RotateSecret generates a new client secret, replaces the stored hash, and returns
// the new plaintext secret with a grace period end timestamp.
func (s *ClientService) RotateSecret(ctx context.Context, clientID string) (*api.AdminClientWithSecret, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get client for rotation: %w", err)
	}

	rawSecret, err := generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client secret: %w", err)
	}

	secretHash, err := s.hasher.Hash(rawSecret)
	if err != nil {
		return nil, fmt.Errorf("hash client secret: %w", err)
	}

	client.SecretHash = secretHash
	client.UpdatedAt = time.Now().UTC()

	updated, err := s.repo.Update(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("update client secret: %w", err)
	}

	graceEnd := time.Now().UTC().Add(secretRotationGracePeriod)
	return &api.AdminClientWithSecret{
		AdminClient:     domainClientToAdminClient(updated),
		ClientSecret:    rawSecret,
		GracePeriodEnds: &graceEnd,
	}, nil
}

// generateClientSecret generates a cryptographically random client secret.
func generateClientSecret() (string, error) {
	b := make([]byte, clientSecretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return clientSecretPrefix + hex.EncodeToString(b), nil
}

// domainClientToAdminClient maps a domain.Client to the api.AdminClient response type.
func domainClientToAdminClient(c *domain.Client) api.AdminClient {
	return api.AdminClient{
		ID:         c.ID.String(),
		Name:       c.Name,
		ClientType: string(c.ClientType),
		Scopes:     c.Scopes,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

// Compile-time assertion.
var _ api.AdminClientService = (*ClientService)(nil)
