package client

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/argon2"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	secretPrefix = "qf_cs_"
	secretBytes  = 32 // 256-bit secret
	saltBytes    = 16 // 128-bit salt
)

// Sentinel errors for the client service layer.
var (
	ErrClientNotFound    = errors.New("client not found")
	ErrInvalidCredentials = errors.New("invalid client credentials")
	ErrClientSuspended   = errors.New("client is suspended")
)

// CreateResult is returned by CreateClient with the plaintext secret.
// The plaintext secret is only available at creation time.
type CreateResult struct {
	Client      *domain.Client
	PlainSecret string
}

// Service implements client management operations.
type Service struct {
	repo   Repository
	argon  config.Argon2Config
	logger *zap.Logger
}

// NewService creates a new client Service.
func NewService(repo Repository, argon config.Argon2Config, logger *zap.Logger) *Service {
	return &Service{
		repo:   repo,
		argon:  argon,
		logger: logger,
	}
}

// CreateClient registers a new OAuth2 client.
// It generates a UUID client_id, a 256-bit qf_cs_-prefixed secret,
// hashes the secret with Argon2id, and stores only the hash.
// The plaintext secret is returned once in CreateResult.
func (s *Service) CreateClient(ctx context.Context, name string, clientType domain.ClientType, scopes []string, owner string, accessTokenTTL int) (*CreateResult, error) {
	if !clientType.IsValid() {
		return nil, fmt.Errorf("invalid client type %q: %w", clientType, ErrInvalidCredentials)
	}

	plainSecret, err := generateSecret()
	if err != nil {
		return nil, fmt.Errorf("generate secret: %w", err)
	}

	hash, err := s.hashSecret(plainSecret)
	if err != nil {
		return nil, fmt.Errorf("hash secret: %w", err)
	}

	now := time.Now().UTC()
	client := &domain.Client{
		ID:             uuid.New(),
		Name:           name,
		ClientType:     clientType,
		SecretHash:     hash,
		Scopes:         scopes,
		Owner:          owner,
		AccessTokenTTL: accessTokenTTL,
		Status:         domain.ClientStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	if err := s.repo.Create(ctx, client); err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	s.logger.Info("client created",
		zap.String("client_id", client.ID.String()),
		zap.String("name", name),
		zap.String("type", string(clientType)),
	)

	return &CreateResult{
		Client:      client,
		PlainSecret: plainSecret,
	}, nil
}

// AuthenticateClient verifies client credentials.
// Returns a generic error for both not-found and wrong-secret to prevent enumeration.
func (s *Service) AuthenticateClient(ctx context.Context, clientID uuid.UUID, secret string) (*domain.Client, error) {
	client, err := s.repo.GetByID(ctx, clientID)
	if err != nil {
		if errors.Is(err, ErrClientNotFound) {
			// Generic error to prevent client enumeration.
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("get client: %w", err)
	}

	if !s.verifySecret(secret, client.SecretHash) {
		return nil, ErrInvalidCredentials
	}

	if !client.IsActive() {
		return nil, ErrClientSuspended
	}

	// Best-effort update; authentication still succeeds if this fails.
	if err := s.repo.UpdateLastUsed(ctx, client.ID); err != nil {
		s.logger.Warn("failed to update last_used_at",
			zap.String("client_id", client.ID.String()),
			zap.Error(err),
		)
	}

	return client, nil
}

// generateSecret produces a 256-bit random secret with the qf_cs_ prefix.
func generateSecret() (string, error) {
	b := make([]byte, secretBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return secretPrefix + hex.EncodeToString(b), nil
}

// hashSecret hashes a plaintext secret using Argon2id with a random salt.
// Format: hex(salt) + "$" + hex(hash)
func (s *Service) hashSecret(plain string) (string, error) {
	salt := make([]byte, saltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	// Prepend pepper to the secret before hashing.
	peppered := s.argon.Pepper + plain

	hash := argon2.IDKey(
		[]byte(peppered),
		salt,
		s.argon.Time,
		s.argon.Memory,
		s.argon.Parallelism,
		secretBytes,
	)

	return hex.EncodeToString(salt) + "$" + hex.EncodeToString(hash), nil
}

// verifySecret checks a plaintext secret against an Argon2id hash.
func (s *Service) verifySecret(plain, encoded string) bool {
	// Split "hex(salt)$hex(hash)".
	var saltHex, hashHex string
	for i := range encoded {
		if encoded[i] == '$' {
			saltHex = encoded[:i]
			hashHex = encoded[i+1:]
			break
		}
	}
	if saltHex == "" || hashHex == "" {
		return false
	}

	salt, err := hex.DecodeString(saltHex)
	if err != nil {
		return false
	}
	expectedHash, err := hex.DecodeString(hashHex)
	if err != nil {
		return false
	}

	peppered := s.argon.Pepper + plain

	actualHash := argon2.IDKey(
		[]byte(peppered),
		salt,
		s.argon.Time,
		s.argon.Memory,
		s.argon.Parallelism,
		secretBytes,
	)

	return subtle.ConstantTimeCompare(actualHash, expectedHash) == 1
}
