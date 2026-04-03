// Package client implements OAuth2 client management and the client credentials grant.
package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// clientSecretPrefix is prepended to generated secrets for leak detection.
	clientSecretPrefix = "qf_cs_"

	// secretBytes is the number of random bytes in a client secret (256 bits).
	secretBytes = 32

	// saltBytes is the number of random bytes for the Argon2id salt.
	saltBytes = 16

	// Argon2id parameters per NIST SP 800-63B / project security profile.
	argon2Memory      uint32 = 19456 // KiB (19 MiB)
	argon2Time        uint32 = 2
	argon2Parallelism uint8  = 1
	argon2KeyLen      uint32 = 32

	// Default access token TTLs by client type (seconds).
	defaultServiceTTL = 900 // 15 minutes
	defaultAgentTTL   = 300 // 5 minutes
)

// TokenIssuer can issue access-only tokens for M2M clients.
// Implemented by *token.Service.
type TokenIssuer interface {
	IssueAccessTokenOnly(ctx context.Context, subject string, scopes []string, clientType string, ttl time.Duration) (*api.AuthResult, error)
}

// Service manages OAuth2 clients and implements the client credentials grant.
// It satisfies api.AdminClientService and api.ClientAuthenticator.
type Service struct {
	repo   storage.ClientRepository
	tokens TokenIssuer
	logger *zap.Logger
}

// NewService creates a new client Service.
func NewService(repo storage.ClientRepository, tokens TokenIssuer, logger *zap.Logger) *Service {
	return &Service{
		repo:   repo,
		tokens: tokens,
		logger: logger,
	}
}

// ── Client Credentials Grant (api.ClientAuthenticator) ─────────────────────

// ClientCredentialsGrant authenticates a client and issues a short-lived access token.
func (s *Service) ClientCredentialsGrant(ctx context.Context, clientID, clientSecret string) (*api.AuthResult, error) {
	client, err := s.authenticateClient(ctx, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("authenticate client: %w", api.ErrUnauthorized)
	}

	result, err := s.tokens.IssueAccessTokenOnly(ctx,
		client.ID.String(),
		client.Scopes,
		string(client.ClientType),
		client.AccessTokenDuration(),
	)
	if err != nil {
		s.logger.Error("failed to issue access token",
			zap.String("client_id", clientID),
			zap.Error(err),
		)
		return nil, fmt.Errorf("issue token: %w", api.ErrInternalError)
	}

	return result, nil
}

// authenticateClient verifies client_id and client_secret, checks status, and
// updates last_used_at. Returns a generic error for both not-found and wrong-secret
// to prevent client enumeration.
func (s *Service) authenticateClient(ctx context.Context, clientID, clientSecret string) (*domain.Client, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		s.logger.Debug("client lookup failed during authentication",
			zap.String("client_id", clientID),
			zap.Error(err),
		)
		return nil, storage.ErrInvalidCredentials
	}

	ok, err := verifySecret(clientSecret, client.SecretHash)
	if err != nil || !ok {
		if err != nil {
			s.logger.Error("secret verification error", zap.Error(err))
		}
		return nil, storage.ErrInvalidCredentials
	}

	if !client.IsActive() {
		return nil, storage.ErrAccountSuspended
	}

	if err := s.repo.UpdateLastUsedAt(ctx, clientID, time.Now().UTC()); err != nil {
		// Non-fatal: log but continue.
		s.logger.Warn("failed to update client last_used_at",
			zap.String("client_id", clientID),
			zap.Error(err),
		)
	}

	return client, nil
}

// ── Admin Operations (api.AdminClientService) ───────────────────────────────

// ListClients returns a paginated list of clients.
func (s *Service) ListClients(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error) {
	clients, total, err := s.repo.List(ctx, page, perPage, includeDeleted)
	if err != nil {
		s.logger.Error("list clients failed", zap.Error(err))
		return nil, fmt.Errorf("list clients: %w", api.ErrInternalError)
	}

	out := make([]api.AdminClient, 0, len(clients))
	for _, c := range clients {
		out = append(out, domainToAdminClient(c))
	}

	return &api.AdminClientList{
		Clients: out,
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}, nil
}

// GetClient retrieves a single client by ID.
func (s *Service) GetClient(ctx context.Context, clientID string) (*api.AdminClient, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("get client: %w", api.ErrInternalError)
	}
	out := domainToAdminClient(client)
	return &out, nil
}

// CreateClient generates a new OAuth2 client with a random secret.
// The plaintext secret is returned only once and never stored.
func (s *Service) CreateClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	clientType := domain.ClientType(req.ClientType)
	if !clientType.IsValid() {
		return nil, fmt.Errorf("invalid client_type %q: %w", req.ClientType, api.ErrInternalError)
	}

	plaintextSecret, secretHash, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client secret: %w", api.ErrInternalError)
	}

	ttl := defaultServiceTTL
	if clientType == domain.ClientTypeAgent {
		ttl = defaultAgentTTL
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:             uuid.New(),
		Name:           req.Name,
		ClientType:     clientType,
		SecretHash:     secretHash,
		Scopes:         req.Scopes,
		Owner:          "",
		AccessTokenTTL: ttl,
		Status:         domain.ClientStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	created, err := s.repo.Create(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateClient) {
			return nil, fmt.Errorf("client name %q already exists: %w", req.Name, api.ErrConflict)
		}
		s.logger.Error("create client failed", zap.Error(err))
		return nil, fmt.Errorf("create client: %w", api.ErrInternalError)
	}

	return &api.AdminClientWithSecret{
		AdminClient:  domainToAdminClient(created),
		ClientSecret: plaintextSecret,
	}, nil
}

// UpdateClient modifies a client's name and/or scopes.
func (s *Service) UpdateClient(ctx context.Context, clientID string, req *api.UpdateClientRequest) (*api.AdminClient, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("find client: %w", api.ErrInternalError)
	}

	if req.Name != nil {
		client.Name = *req.Name
	}
	if req.Scopes != nil {
		client.Scopes = req.Scopes
	}

	updated, err := s.repo.Update(ctx, client)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrDuplicateClient) {
			return nil, fmt.Errorf("client name already taken: %w", api.ErrConflict)
		}
		s.logger.Error("update client failed", zap.Error(err))
		return nil, fmt.Errorf("update client: %w", api.ErrInternalError)
	}

	out := domainToAdminClient(updated)
	return &out, nil
}

// DeleteClient soft-deletes a client by setting its status to "revoked".
func (s *Service) DeleteClient(ctx context.Context, clientID string) error {
	if err := s.repo.Delete(ctx, clientID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		s.logger.Error("delete client failed", zap.Error(err))
		return fmt.Errorf("delete client: %w", api.ErrInternalError)
	}
	return nil
}

// RotateSecret generates a new client secret and replaces the stored hash.
// The old secret is immediately invalidated. The new plaintext secret is
// returned once and never stored.
func (s *Service) RotateSecret(ctx context.Context, clientID string) (*api.AdminClientWithSecret, error) {
	client, err := s.repo.FindByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("client %s: %w", clientID, api.ErrNotFound)
		}
		return nil, fmt.Errorf("find client: %w", api.ErrInternalError)
	}

	plaintextSecret, secretHash, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate new secret: %w", api.ErrInternalError)
	}

	client.SecretHash = secretHash
	updated, err := s.repo.Update(ctx, client)
	if err != nil {
		s.logger.Error("rotate secret failed", zap.Error(err))
		return nil, fmt.Errorf("rotate secret: %w", api.ErrInternalError)
	}

	return &api.AdminClientWithSecret{
		AdminClient:  domainToAdminClient(updated),
		ClientSecret: plaintextSecret,
	}, nil
}

// ── Internal helpers ─────────────────────────────────────────────────────────

// generateSecret produces a cryptographically random 256-bit client secret
// prefixed with "qf_cs_", and returns both the plaintext and its Argon2id hash.
func generateSecret() (plaintext, hash string, err error) {
	raw := make([]byte, secretBytes)
	if _, err = rand.Read(raw); err != nil {
		return "", "", fmt.Errorf("crypto/rand: %w", err)
	}

	plaintext = clientSecretPrefix + base64.RawURLEncoding.EncodeToString(raw)

	hash, err = hashSecret(plaintext)
	if err != nil {
		return "", "", fmt.Errorf("hash secret: %w", err)
	}

	return plaintext, hash, nil
}

// hashSecret hashes a secret with Argon2id and returns a PHC-format string.
// Format: $argon2id$v=<version>$m=<memory>,t=<time>,p=<parallelism>$<salt_b64>$<hash_b64>
func hashSecret(secret string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	hash := argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Parallelism, argon2KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argon2Memory, argon2Time, argon2Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// verifySecret verifies a plaintext secret against an Argon2id PHC hash string.
func verifySecret(secret, encoded string) (bool, error) {
	// $argon2id$v=19$m=<M>,t=<T>,p=<P>$<salt_b64>$<hash_b64>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return false, fmt.Errorf("invalid hash format")
	}

	var m, t, p int
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
		return false, fmt.Errorf("parse argon2 params: %w", err)
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, fmt.Errorf("decode salt: %w", err)
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, fmt.Errorf("decode hash: %w", err)
	}

	computed := argon2.IDKey(
		[]byte(secret), salt,
		uint32(t), uint32(m), uint8(p), //nolint:gosec // parsed from trusted PHC string
		uint32(len(expectedHash)),
	)

	return subtle.ConstantTimeCompare(computed, expectedHash) == 1, nil
}

// domainToAdminClient converts a domain.Client to an api.AdminClient response type.
func domainToAdminClient(c *domain.Client) api.AdminClient {
	return api.AdminClient{
		ID:         c.ID.String(),
		Name:       c.Name,
		ClientType: string(c.ClientType),
		Scopes:     c.Scopes,
		CreatedAt:  c.CreatedAt,
		UpdatedAt:  c.UpdatedAt,
	}
}

// Compile-time interface checks.
var _ api.AdminClientService = (*Service)(nil)
var _ api.ClientAuthenticator = (*Service)(nil)
