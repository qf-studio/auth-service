// Package apikey provides business logic for API key lifecycle management
// including creation, validation, rotation, revocation, and per-key rate limiting.
package apikey

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/password"
)

const (
	// apiKeyPrefix is prepended to generated API keys for leak detection.
	apiKeyPrefix = "qf_ak_"
	// apiKeyBytes is the number of random bytes (128 bits = 16 bytes).
	apiKeyBytes = 16
	// gracePeriodDuration is the grace period for previous keys after rotation.
	gracePeriodDuration = 24 * time.Hour
	// rateLimitKeyPrefix is the Redis key prefix for per-key rate limiting.
	rateLimitKeyPrefix = "rl:ak:"
	// rateLimitWindow is the sliding window duration for rate limiting.
	rateLimitWindow = 1 * time.Minute
)

// Audit event types for API key operations.
const (
	EventAPIKeyCreate = "apikey_create"
	EventAPIKeyRotate = "apikey_rotate"
	EventAPIKeyRevoke = "apikey_revoke"
)

// Repository defines the storage interface for API keys.
type Repository interface {
	Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.APIKey, error)
	FindByKeyHash(ctx context.Context, keyHash string) (*domain.APIKey, error)
	UpdateLastUsed(ctx context.Context, id uuid.UUID, t time.Time) error
	RotateKey(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
	Revoke(ctx context.Context, id uuid.UUID) error
}

// RateLimitInfo contains rate limit state returned after validation.
type RateLimitInfo struct {
	Limit     int   // max requests per window
	Remaining int   // requests left in current window
	ResetAt   int64 // unix timestamp when the window resets
}

// CreateResult is returned by CreateAPIKey with the plaintext key shown once.
type CreateResult struct {
	APIKey      *domain.APIKey
	PlaintextKey string
}

// RotateResult is returned by RotateKey with the new plaintext key.
type RotateResult struct {
	APIKey          *domain.APIKey
	PlaintextKey    string
	GracePeriodEnds time.Time
}

// Service implements API key business logic.
type Service struct {
	repo   Repository
	hasher password.Hasher
	rdb    *redis.Client
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewService creates a new API key service.
func NewService(repo Repository, hasher password.Hasher, rdb *redis.Client, logger *zap.Logger, auditor audit.EventLogger) *Service {
	return &Service{
		repo:   repo,
		hasher: hasher,
		rdb:    rdb,
		logger: logger,
		audit:  auditor,
	}
}

// CreateAPIKey generates a new API key with the qf_ak_ prefix, hashes it with
// Argon2id, and stores only the hash. The plaintext key is returned once.
func (s *Service) CreateAPIKey(ctx context.Context, clientID uuid.UUID, name string, scopes []string, rateLimit int, expiresAt *time.Time) (*CreateResult, error) {
	plaintext, err := generateAPIKey()
	if err != nil {
		s.logger.Error("generate api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", err)
	}

	hash, err := s.hasher.Hash(plaintext)
	if err != nil {
		s.logger.Error("hash api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", err)
	}

	now := time.Now().UTC()
	if scopes == nil {
		scopes = []string{}
	}

	key := &domain.APIKey{
		ID:        uuid.New(),
		ClientID:  clientID,
		Name:      name,
		KeyHash:   hash,
		Scopes:    scopes,
		RateLimit: rateLimit,
		Status:    domain.APIKeyStatusActive,
		ExpiresAt: expiresAt,
		CreatedAt: now,
		UpdatedAt: now,
	}

	created, err := s.repo.Create(ctx, key)
	if err != nil {
		s.logger.Error("store api key failed", zap.Error(err))
		return nil, fmt.Errorf("create api key: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventAPIKeyCreate,
		TargetID: created.ID.String(),
		Metadata: map[string]string{
			"client_id": clientID.String(),
			"name":      name,
		},
	})

	return &CreateResult{
		APIKey:       created,
		PlaintextKey: plaintext,
	}, nil
}

// ValidateAPIKey hashes the provided key, looks it up by hash (checking both
// current and previous key hashes during grace period), verifies expiry/status,
// updates last_used_at, and checks per-key rate limits.
func (s *Service) ValidateAPIKey(ctx context.Context, plaintextKey string) (*domain.APIKey, *RateLimitInfo, error) {
	hash, err := s.hasher.Hash(plaintextKey)
	if err != nil {
		return nil, nil, fmt.Errorf("validate api key: %w", err)
	}

	key, err := s.repo.FindByKeyHash(ctx, hash)
	if err != nil {
		if isNotFound(err) {
			return nil, nil, domain.ErrAPIKeyNotFound
		}
		s.logger.Error("find api key by hash failed", zap.Error(err))
		return nil, nil, fmt.Errorf("validate api key: %w", err)
	}

	if key.Status == domain.APIKeyStatusRevoked {
		return nil, nil, domain.ErrAPIKeyRevoked
	}

	if key.IsExpired() {
		return nil, nil, domain.ErrAPIKeyExpired
	}

	// Check per-key rate limit.
	rlInfo, err := s.checkRateLimit(ctx, key.ID.String(), key.RateLimit)
	if err != nil {
		s.logger.Error("rate limit check failed", zap.String("key_id", key.ID.String()), zap.Error(err))
		return nil, nil, fmt.Errorf("validate api key: %w", err)
	}

	if rlInfo.Remaining < 0 {
		return nil, rlInfo, domain.ErrAPIKeyRateLimited
	}

	// Update last_used_at asynchronously (best-effort).
	now := time.Now().UTC()
	if updateErr := s.repo.UpdateLastUsed(ctx, key.ID, now); updateErr != nil {
		s.logger.Warn("update last_used_at failed", zap.String("key_id", key.ID.String()), zap.Error(updateErr))
	}

	return key, rlInfo, nil
}

// RotateKey creates a new key, moves the current hash to previous_key_hash
// with a 24-hour grace period.
func (s *Service) RotateKey(ctx context.Context, keyID uuid.UUID) (*RotateResult, error) {
	existing, err := s.repo.FindByID(ctx, keyID)
	if err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("key %s: %w", keyID, domain.ErrAPIKeyNotFound)
		}
		s.logger.Error("find api key for rotation failed", zap.String("key_id", keyID.String()), zap.Error(err))
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	if existing.Status == domain.APIKeyStatusRevoked {
		return nil, fmt.Errorf("key %s: %w", keyID, domain.ErrAPIKeyRevoked)
	}

	plaintext, err := generateAPIKey()
	if err != nil {
		s.logger.Error("generate api key for rotation failed", zap.Error(err))
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	hash, err := s.hasher.Hash(plaintext)
	if err != nil {
		s.logger.Error("hash api key for rotation failed", zap.Error(err))
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	graceEnd := time.Now().UTC().Add(gracePeriodDuration)

	if err := s.repo.RotateKey(ctx, keyID, hash, graceEnd); err != nil {
		if isNotFound(err) {
			return nil, fmt.Errorf("key %s: %w", keyID, domain.ErrAPIKeyNotFound)
		}
		s.logger.Error("rotate key failed", zap.String("key_id", keyID.String()), zap.Error(err))
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	// Re-read the key to get updated state.
	updated, err := s.repo.FindByID(ctx, keyID)
	if err != nil {
		s.logger.Error("re-read key after rotation failed", zap.String("key_id", keyID.String()), zap.Error(err))
		return nil, fmt.Errorf("rotate key: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventAPIKeyRotate,
		TargetID: keyID.String(),
		Metadata: map[string]string{
			"client_id": existing.ClientID.String(),
		},
	})

	return &RotateResult{
		APIKey:          updated,
		PlaintextKey:    plaintext,
		GracePeriodEnds: graceEnd,
	}, nil
}

// RevokeKey soft-deletes an API key by setting its status to revoked.
func (s *Service) RevokeKey(ctx context.Context, keyID uuid.UUID) error {
	existing, err := s.repo.FindByID(ctx, keyID)
	if err != nil {
		if isNotFound(err) {
			return fmt.Errorf("key %s: %w", keyID, domain.ErrAPIKeyNotFound)
		}
		s.logger.Error("find api key for revocation failed", zap.String("key_id", keyID.String()), zap.Error(err))
		return fmt.Errorf("revoke key: %w", err)
	}

	if existing.Status == domain.APIKeyStatusRevoked {
		return fmt.Errorf("key %s already revoked: %w", keyID, domain.ErrAPIKeyRevoked)
	}

	if err := s.repo.Revoke(ctx, keyID); err != nil {
		if isNotFound(err) {
			return fmt.Errorf("key %s: %w", keyID, domain.ErrAPIKeyNotFound)
		}
		s.logger.Error("revoke key failed", zap.String("key_id", keyID.String()), zap.Error(err))
		return fmt.Errorf("revoke key: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     EventAPIKeyRevoke,
		TargetID: keyID.String(),
		Metadata: map[string]string{
			"client_id": existing.ClientID.String(),
		},
	})

	return nil
}

// checkRateLimit uses a Redis sliding window to enforce per-key rate limits.
// Returns rate limit info including remaining requests and window reset time.
func (s *Service) checkRateLimit(ctx context.Context, keyID string, limit int) (*RateLimitInfo, error) {
	if limit <= 0 {
		// No rate limit configured for this key.
		return &RateLimitInfo{Limit: 0, Remaining: 0, ResetAt: 0}, nil
	}

	redisKey := rateLimitKeyPrefix + keyID
	now := time.Now().UTC()
	windowStart := now.Add(-rateLimitWindow)
	resetAt := now.Add(rateLimitWindow).Unix()

	pipe := s.rdb.Pipeline()

	// Remove entries outside the current window.
	pipe.ZRemRangeByScore(ctx, redisKey, "0", fmt.Sprintf("%d", windowStart.UnixNano()))

	// Count current entries in the window.
	countCmd := pipe.ZCard(ctx, redisKey)

	// Add the current request with the current timestamp as score.
	member := fmt.Sprintf("%d:%s", now.UnixNano(), uuid.New().String()[:8])
	pipe.ZAdd(ctx, redisKey, redis.Z{Score: float64(now.UnixNano()), Member: member})

	// Set TTL on the key to auto-expire after the window.
	pipe.Expire(ctx, redisKey, rateLimitWindow+time.Second)

	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("rate limit check: %w", err)
	}

	count := int(countCmd.Val())
	remaining := limit - count - 1 // -1 because we just added one

	return &RateLimitInfo{
		Limit:     limit,
		Remaining: remaining,
		ResetAt:   resetAt,
	}, nil
}

// generateAPIKey creates a cryptographically random API key with the qf_ak_ prefix.
func generateAPIKey() (string, error) {
	b := make([]byte, apiKeyBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}
	return apiKeyPrefix + hex.EncodeToString(b), nil
}

// isNotFound checks for common "not found" sentinel errors.
func isNotFound(err error) bool {
	return errors.Is(err, domain.ErrAPIKeyNotFound)
}
