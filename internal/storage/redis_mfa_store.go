package storage

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// mfaTokenPrefix is the Redis key prefix for temporary MFA tokens.
	mfaTokenPrefix = "mfa:token:"

	// mfaFailedPrefix is the Redis key prefix for failed MFA attempt counters.
	mfaFailedPrefix = "mfa:failed:"

	// webauthnChallengePrefix is the Redis key prefix for WebAuthn challenge/session data.
	webauthnChallengePrefix = "webauthn:challenge:"

	// defaultMFATokenTTL is the lifetime of a temporary MFA token (5 minutes).
	defaultMFATokenTTL = 5 * time.Minute

	// defaultMFAFailedTTL is the window for tracking failed attempts (15 minutes).
	defaultMFAFailedTTL = 15 * time.Minute

	// defaultMaxMFAAttempts is the maximum allowed failed MFA attempts before lockout.
	defaultMaxMFAAttempts = 5

	// defaultWebAuthnChallengeTTL is the lifetime of a WebAuthn challenge (60 seconds).
	defaultWebAuthnChallengeTTL = 60 * time.Second
)

// RedisMFAStore manages temporary MFA tokens, failed-attempt tracking,
// and WebAuthn challenge/session data in Redis.
type RedisMFAStore struct {
	client            redis.Cmdable
	tokenTTL          time.Duration
	failedTTL         time.Duration
	maxAttempts       int
	webauthnChallTTL  time.Duration
}

// RedisMFAStoreOption configures the RedisMFAStore.
type RedisMFAStoreOption func(*RedisMFAStore)

// WithMFATokenTTL overrides the default MFA token TTL.
func WithMFATokenTTL(d time.Duration) RedisMFAStoreOption {
	return func(s *RedisMFAStore) { s.tokenTTL = d }
}

// WithMFAFailedTTL overrides the default failed-attempt window.
func WithMFAFailedTTL(d time.Duration) RedisMFAStoreOption {
	return func(s *RedisMFAStore) { s.failedTTL = d }
}

// WithMaxMFAAttempts overrides the maximum allowed failed attempts.
func WithMaxMFAAttempts(n int) RedisMFAStoreOption {
	return func(s *RedisMFAStore) { s.maxAttempts = n }
}

// WithWebAuthnChallengeTTL overrides the default WebAuthn challenge TTL.
func WithWebAuthnChallengeTTL(d time.Duration) RedisMFAStoreOption {
	return func(s *RedisMFAStore) { s.webauthnChallTTL = d }
}

// NewRedisMFAStore creates a new Redis-backed MFA token store.
func NewRedisMFAStore(client redis.Cmdable, opts ...RedisMFAStoreOption) *RedisMFAStore {
	s := &RedisMFAStore{
		client:           client,
		tokenTTL:         defaultMFATokenTTL,
		failedTTL:        defaultMFAFailedTTL,
		maxAttempts:      defaultMaxMFAAttempts,
		webauthnChallTTL: defaultWebAuthnChallengeTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// StoreMFAToken saves a temporary MFA token mapping to a user ID.
// The token is single-use and expires after the configured TTL.
func (s *RedisMFAStore) StoreMFAToken(ctx context.Context, token, userID string) error {
	key := mfaTokenPrefix + token
	ok, err := s.client.SetNX(ctx, key, userID, s.tokenTTL).Result()
	if err != nil {
		return fmt.Errorf("store mfa token: %w", err)
	}
	if !ok {
		return fmt.Errorf("mfa token already exists: %w", ErrDuplicateMFA)
	}
	return nil
}

// ConsumeMFAToken retrieves and deletes the MFA token in a single atomic operation.
// Returns the associated user ID. Returns ErrMFATokenNotFound if the token
// does not exist or has already been consumed.
func (s *RedisMFAStore) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	key := mfaTokenPrefix + token
	userID, err := s.client.GetDel(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return "", ErrMFATokenNotFound
		}
		return "", fmt.Errorf("consume mfa token: %w", err)
	}
	return userID, nil
}

// RecordFailedAttempt increments the failed attempt counter for a user.
// Returns ErrMFAMaxAttempts if the user has exceeded the maximum allowed attempts.
func (s *RedisMFAStore) RecordFailedAttempt(ctx context.Context, userID string) (int, error) {
	key := mfaFailedPrefix + userID

	count, err := s.client.Incr(ctx, key).Result()
	if err != nil {
		return 0, fmt.Errorf("increment mfa failed attempts: %w", err)
	}

	// Set TTL on first attempt.
	if count == 1 {
		if err := s.client.Expire(ctx, key, s.failedTTL).Err(); err != nil {
			return int(count), fmt.Errorf("set mfa failed ttl: %w", err)
		}
	}

	if int(count) >= s.maxAttempts {
		return int(count), ErrMFAMaxAttempts
	}

	return int(count), nil
}

// GetFailedAttempts returns the current failed attempt count for a user.
func (s *RedisMFAStore) GetFailedAttempts(ctx context.Context, userID string) (int, error) {
	key := mfaFailedPrefix + userID
	val, err := s.client.Get(ctx, key).Result()
	if err != nil {
		if err == redis.Nil {
			return 0, nil
		}
		return 0, fmt.Errorf("get mfa failed attempts: %w", err)
	}

	count, err := strconv.Atoi(val)
	if err != nil {
		return 0, fmt.Errorf("parse mfa failed attempts: %w", err)
	}

	return count, nil
}

// ClearFailedAttempts resets the failed attempt counter for a user (e.g. after successful MFA).
func (s *RedisMFAStore) ClearFailedAttempts(ctx context.Context, userID string) error {
	key := mfaFailedPrefix + userID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("clear mfa failed attempts: %w", err)
	}
	return nil
}

// ────────────────────────────────────────────────────────────────────────────
// WebAuthn challenge / session data
// ────────────────────────────────────────────────────────────────────────────

// StoreWebAuthnChallenge saves WebAuthn challenge/session data keyed by session ID.
// The data expires after the configured WebAuthn challenge TTL (default 60s).
func (s *RedisMFAStore) StoreWebAuthnChallenge(ctx context.Context, sessionID string, data []byte) error {
	key := webauthnChallengePrefix + sessionID
	ok, err := s.client.SetNX(ctx, key, data, s.webauthnChallTTL).Result()
	if err != nil {
		return fmt.Errorf("store webauthn challenge: %w", err)
	}
	if !ok {
		return fmt.Errorf("session %s: webauthn challenge already exists", sessionID)
	}
	return nil
}

// GetWebAuthnChallenge retrieves WebAuthn challenge/session data without consuming it.
// Returns ErrWebAuthnChallengeNotFound if the session has expired or does not exist.
func (s *RedisMFAStore) GetWebAuthnChallenge(ctx context.Context, sessionID string) ([]byte, error) {
	key := webauthnChallengePrefix + sessionID
	data, err := s.client.Get(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrWebAuthnChallengeNotFound
		}
		return nil, fmt.Errorf("get webauthn challenge: %w", err)
	}
	return data, nil
}

// ConsumeWebAuthnChallenge retrieves and deletes the challenge data atomically.
// Returns ErrWebAuthnChallengeNotFound if the session has expired or does not exist.
func (s *RedisMFAStore) ConsumeWebAuthnChallenge(ctx context.Context, sessionID string) ([]byte, error) {
	key := webauthnChallengePrefix + sessionID
	data, err := s.client.GetDel(ctx, key).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrWebAuthnChallengeNotFound
		}
		return nil, fmt.Errorf("consume webauthn challenge: %w", err)
	}
	return data, nil
}

// DeleteWebAuthnChallenge removes a WebAuthn challenge/session entry.
func (s *RedisMFAStore) DeleteWebAuthnChallenge(ctx context.Context, sessionID string) error {
	key := webauthnChallengePrefix + sessionID
	if err := s.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("delete webauthn challenge: %w", err)
	}
	return nil
}
