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
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// apiKeyPrefix is prepended to generated API keys for leak detection.
	apiKeyPrefix = "qf_ak_"
	// apiKeyBytes is the number of random bytes for API key generation (128-bit).
	apiKeyBytes = 16
	// apiKeyGracePeriod is the grace period after key rotation.
	apiKeyGracePeriod = 24 * time.Hour
	// defaultRateLimit is the default per-key rate limit (requests/minute).
	defaultRateLimit = 1000
)

// APIKeyService implements api.AdminAPIKeyService.
type APIKeyService struct {
	repo   storage.APIKeyRepository
	hasher password.Hasher
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewAPIKeyService creates a new admin API key service.
func NewAPIKeyService(repo storage.APIKeyRepository, hasher password.Hasher, logger *zap.Logger, auditor audit.EventLogger) *APIKeyService {
	return &APIKeyService{
		repo:   repo,
		hasher: hasher,
		logger: logger,
		audit:  auditor,
	}
}

// ListAPIKeys returns a paginated list of API keys, optionally filtered by client_id.
func (s *APIKeyService) ListAPIKeys(ctx context.Context, page, perPage int, clientID string) (*api.AdminAPIKeyList, error) {
	offset := (page - 1) * perPage

	keys, total, err := s.repo.List(ctx, perPage, offset, clientID)
	if err != nil {
		s.logger.Error("list api keys failed", zap.Error(err))
		return nil, fmt.Errorf("list api keys: %w", api.ErrInternalError)
	}

	result := &api.AdminAPIKeyList{
		APIKeys: make([]api.AdminAPIKey, 0, len(keys)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	for _, k := range keys {
		result.APIKeys = append(result.APIKeys, domainAPIKeyToAdmin(k))
	}

	return result, nil
}

// GetAPIKey retrieves a single API key by ID.
func (s *APIKeyService) GetAPIKey(ctx context.Context, keyID string) (*api.AdminAPIKey, error) {
	id, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid api key ID: %w", api.ErrNotFound)
	}

	k, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", keyID, api.ErrNotFound)
		}
		s.logger.Error("get api key failed", zap.String("key_id", keyID), zap.Error(err))
		return nil, fmt.Errorf("get api key: %w", api.ErrInternalError)
	}

	admin := domainAPIKeyToAdmin(k)
	return &admin, nil
}

// CreateAPIKey creates a new API key with a generated raw key.
func (s *APIKeyService) CreateAPIKey(ctx context.Context, req *api.CreateAPIKeyRequest) (*api.AdminAPIKeyWithSecret, error) {
	clientID, err := uuid.Parse(req.ClientID)
	if err != nil {
		return nil, fmt.Errorf("invalid client ID: %w", api.ErrNotFound)
	}

	rawKey, err := generateAPIKey()
	if err != nil {
		s.logger.Error("generate api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", api.ErrInternalError)
	}

	hash, err := s.hasher.Hash(rawKey)
	if err != nil {
		s.logger.Error("hash api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", api.ErrInternalError)
	}

	now := time.Now().UTC()
	scopes := req.Scopes
	if scopes == nil {
		scopes = []string{}
	}

	rateLimit := defaultRateLimit
	if req.RateLimit != nil {
		rateLimit = *req.RateLimit
	}

	// Store the first 8 characters of the key for identification.
	keyPrefix := rawKey[:len(apiKeyPrefix)+8]

	var expiresAt *time.Time
	if req.ExpiresAt != nil {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			return nil, fmt.Errorf("invalid expires_at format (use RFC3339): %w", api.ErrConflict)
		}
		expiresAt = &t
	}

	tenantID := middleware.TenantIDFromStdContext(ctx)

	key := &domain.APIKey{
		ID:        uuid.New(),
		TenantID:  uuidFromString(tenantID),
		ClientID:  clientID,
		Name:      req.Name,
		KeyHash:   hash,
		KeyPrefix: keyPrefix,
		Scopes:    scopes,
		RateLimit: rateLimit,
		Status:    domain.APIKeyStatusActive,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	created, err := s.repo.Create(ctx, key)
	if err != nil {
		s.logger.Error("create api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminAPIKeyCreate,
		TargetID: created.ID.String(),
		Metadata: map[string]string{"name": created.Name, "client_id": created.ClientID.String()},
	})

	return &api.AdminAPIKeyWithSecret{
		AdminAPIKey: domainAPIKeyToAdmin(created),
		Key:         rawKey,
	}, nil
}

// UpdateAPIKey modifies API key fields (name, scopes, rate_limit).
func (s *APIKeyService) UpdateAPIKey(ctx context.Context, keyID string, req *api.UpdateAPIKeyRequest) (*api.AdminAPIKey, error) {
	id, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid api key ID: %w", api.ErrNotFound)
	}

	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", keyID, api.ErrNotFound)
		}
		s.logger.Error("find api key for update failed", zap.String("key_id", keyID), zap.Error(err))
		return nil, fmt.Errorf("update api key: %w", api.ErrInternalError)
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Scopes != nil {
		existing.Scopes = req.Scopes
	}
	if req.RateLimit != nil {
		existing.RateLimit = *req.RateLimit
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", keyID, api.ErrNotFound)
		}
		s.logger.Error("update api key failed", zap.String("key_id", keyID), zap.Error(err))
		return nil, fmt.Errorf("update api key: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminAPIKeyUpdate,
		TargetID: keyID,
	})

	admin := domainAPIKeyToAdmin(updated)
	return &admin, nil
}

// RevokeAPIKey marks an API key as revoked.
func (s *APIKeyService) RevokeAPIKey(ctx context.Context, keyID string) error {
	id, err := uuid.Parse(keyID)
	if err != nil {
		return fmt.Errorf("invalid api key ID: %w", api.ErrNotFound)
	}

	err = s.repo.Revoke(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("api key %s: %w", keyID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrAlreadyDeleted) {
			return fmt.Errorf("api key %s already revoked: %w", keyID, api.ErrConflict)
		}
		s.logger.Error("revoke api key failed", zap.String("key_id", keyID), zap.Error(err))
		return fmt.Errorf("revoke api key: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminAPIKeyRevoke,
		TargetID: keyID,
	})
	return nil
}

// RotateAPIKey generates a new key for the API key with a grace period.
func (s *APIKeyService) RotateAPIKey(ctx context.Context, keyID string) (*api.AdminAPIKeyWithSecret, error) {
	id, err := uuid.Parse(keyID)
	if err != nil {
		return nil, fmt.Errorf("invalid api key ID: %w", api.ErrNotFound)
	}

	rawKey, err := generateAPIKey()
	if err != nil {
		s.logger.Error("generate api key failed", zap.Error(err))
		return nil, fmt.Errorf("rotate api key: %w", api.ErrInternalError)
	}

	hash, err := s.hasher.Hash(rawKey)
	if err != nil {
		s.logger.Error("hash api key failed", zap.Error(err))
		return nil, fmt.Errorf("rotate api key: %w", api.ErrInternalError)
	}

	graceEnd := time.Now().UTC().Add(apiKeyGracePeriod)

	if err := s.repo.RotateKey(ctx, id, hash, graceEnd); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("api key %s: %w", keyID, api.ErrNotFound)
		}
		s.logger.Error("rotate api key failed", zap.String("key_id", keyID), zap.Error(err))
		return nil, fmt.Errorf("rotate api key: %w", api.ErrInternalError)
	}

	key, err := s.repo.FindByID(ctx, id)
	if err != nil {
		s.logger.Error("re-read api key after rotation failed", zap.String("key_id", keyID), zap.Error(err))
		return nil, fmt.Errorf("rotate api key: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminAPIKeyRotate,
		TargetID: keyID,
	})

	return &api.AdminAPIKeyWithSecret{
		AdminAPIKey:     domainAPIKeyToAdmin(key),
		Key:             rawKey,
		GracePeriodEnds: &graceEnd,
	}, nil
}

// ValidateAPIKey validates a raw API key and returns its metadata.
// This method satisfies middleware.APIKeyValidator.
func (s *APIKeyService) ValidateAPIKey(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error) {
	hash, err := s.hasher.Hash(rawKey)
	if err != nil {
		s.logger.Error("hash api key for validation failed", zap.Error(err))
		return nil, fmt.Errorf("validate api key: %w", err)
	}

	key, err := s.repo.FindByKeyHash(ctx, hash)
	if err != nil {
		return nil, fmt.Errorf("validate api key: %w", err)
	}

	if !key.IsActive() {
		return nil, fmt.Errorf("api key is not active")
	}

	// Best-effort update of last_used_at.
	_ = s.repo.UpdateLastUsed(ctx, key.ID)

	return &middleware.APIKeyInfo{
		ClientID:  key.ClientID.String(),
		Scopes:    key.Scopes,
		RateLimit: key.RateLimit,
	}, nil
}

// generateAPIKey generates a cryptographically random API key with the qf_ak_ prefix.
func generateAPIKey() (string, error) {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return apiKeyPrefix + hex.EncodeToString(b), nil
}

// domainAPIKeyToAdmin converts a domain.APIKey to an api.AdminAPIKey response DTO.
func domainAPIKeyToAdmin(k *domain.APIKey) api.AdminAPIKey {
	return api.AdminAPIKey{
		ID:         k.ID.String(),
		ClientID:   k.ClientID.String(),
		Name:       k.Name,
		KeyPrefix:  k.KeyPrefix,
		Scopes:     k.Scopes,
		RateLimit:  k.RateLimit,
		Status:     k.Status,
		ExpiresAt:  k.ExpiresAt,
		LastUsedAt: k.LastUsedAt,
		CreatedAt:  k.CreatedAt,
		UpdatedAt:  k.UpdatedAt,
	}
}
