package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// loginRequestPrefix namespaces login request keys in Redis.
	loginRequestPrefix = "oidc:login:"

	// consentRequestPrefix namespaces consent request keys in Redis.
	consentRequestPrefix = "oidc:consent:"

	// authorizationCodePrefix namespaces authorization code keys in Redis.
	authorizationCodePrefix = "oidc:code:"

	// defaultChallengeTTL is the lifetime of login and consent challenges (10 minutes).
	defaultChallengeTTL = 10 * time.Minute

	// defaultCodeTTL is the lifetime of an authorization code (60 seconds).
	defaultCodeTTL = 60 * time.Second
)

// RedisStore is a Redis-backed store for the ephemeral OIDC provider state:
// login requests, consent requests, and authorization codes.
//
// Authorization codes are always single-use, retrieved via GETDEL. Login and
// consent requests support both a non-destructive Get (for repeated reads by
// the login/consent UI while the challenge is pending) and a one-time
// Consume (GETDEL) for the accept/reject transition.
type RedisStore struct {
	client       redis.Cmdable
	challengeTTL time.Duration
	codeTTL      time.Duration
}

// RedisStoreOption configures a RedisStore.
type RedisStoreOption func(*RedisStore)

// WithChallengeTTL overrides the default login/consent challenge TTL.
func WithChallengeTTL(d time.Duration) RedisStoreOption {
	return func(s *RedisStore) { s.challengeTTL = d }
}

// WithCodeTTL overrides the default authorization code TTL.
func WithCodeTTL(d time.Duration) RedisStoreOption {
	return func(s *RedisStore) { s.codeTTL = d }
}

// NewRedisStore creates a new Redis-backed OIDC provider store.
func NewRedisStore(client redis.Cmdable, opts ...RedisStoreOption) *RedisStore {
	s := &RedisStore{
		client:       client,
		challengeTTL: defaultChallengeTTL,
		codeTTL:      defaultCodeTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// ────────────────────────────────────────────────────────────────────────────
// Login requests
// ────────────────────────────────────────────────────────────────────────────

// SaveLoginRequest stores a login request keyed by its challenge, expiring
// after the configured challenge TTL.
func (s *RedisStore) SaveLoginRequest(ctx context.Context, lr *LoginRequest) error {
	data, err := json.Marshal(lr)
	if err != nil {
		return fmt.Errorf("marshal login request: %w", err)
	}
	if err := s.client.Set(ctx, loginRequestPrefix+lr.Challenge, data, s.challengeTTL).Err(); err != nil {
		return fmt.Errorf("save login request: %w", err)
	}
	return nil
}

// GetLoginRequest returns the login request for the given challenge without
// consuming it. Returns ErrLoginRequestNotFound if it does not exist or has
// expired.
func (s *RedisStore) GetLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error) {
	data, err := s.client.Get(ctx, loginRequestPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrLoginRequestNotFound
		}
		return nil, fmt.Errorf("get login request: %w", err)
	}
	var lr LoginRequest
	if err := json.Unmarshal(data, &lr); err != nil {
		return nil, fmt.Errorf("unmarshal login request: %w", err)
	}
	return &lr, nil
}

// ConsumeLoginRequest atomically retrieves and deletes the login request for
// the given challenge (GETDEL), enforcing one-time use for the accept/reject
// transition. Returns ErrLoginRequestNotFound if it does not exist, has
// expired, or was already consumed.
func (s *RedisStore) ConsumeLoginRequest(ctx context.Context, challenge string) (*LoginRequest, error) {
	data, err := s.client.GetDel(ctx, loginRequestPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrLoginRequestNotFound
		}
		return nil, fmt.Errorf("consume login request: %w", err)
	}
	var lr LoginRequest
	if err := json.Unmarshal(data, &lr); err != nil {
		return nil, fmt.Errorf("unmarshal login request: %w", err)
	}
	return &lr, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Consent requests
// ────────────────────────────────────────────────────────────────────────────

// SaveConsentRequest stores a consent request keyed by its challenge,
// expiring after the configured challenge TTL.
func (s *RedisStore) SaveConsentRequest(ctx context.Context, cr *ConsentRequest) error {
	data, err := json.Marshal(cr)
	if err != nil {
		return fmt.Errorf("marshal consent request: %w", err)
	}
	if err := s.client.Set(ctx, consentRequestPrefix+cr.Challenge, data, s.challengeTTL).Err(); err != nil {
		return fmt.Errorf("save consent request: %w", err)
	}
	return nil
}

// GetConsentRequest returns the consent request for the given challenge
// without consuming it. Returns ErrConsentRequestNotFound if it does not
// exist or has expired.
func (s *RedisStore) GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error) {
	data, err := s.client.Get(ctx, consentRequestPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrConsentRequestNotFound
		}
		return nil, fmt.Errorf("get consent request: %w", err)
	}
	var cr ConsentRequest
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("unmarshal consent request: %w", err)
	}
	return &cr, nil
}

// ConsumeConsentRequest atomically retrieves and deletes the consent request
// for the given challenge (GETDEL), enforcing one-time use for the
// accept/reject transition. Returns ErrConsentRequestNotFound if it does not
// exist, has expired, or was already consumed.
func (s *RedisStore) ConsumeConsentRequest(ctx context.Context, challenge string) (*ConsentRequest, error) {
	data, err := s.client.GetDel(ctx, consentRequestPrefix+challenge).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrConsentRequestNotFound
		}
		return nil, fmt.Errorf("consume consent request: %w", err)
	}
	var cr ConsentRequest
	if err := json.Unmarshal(data, &cr); err != nil {
		return nil, fmt.Errorf("unmarshal consent request: %w", err)
	}
	return &cr, nil
}

// ────────────────────────────────────────────────────────────────────────────
// Authorization codes
// ────────────────────────────────────────────────────────────────────────────

// SaveAuthorizationCode stores an authorization code, expiring after the
// configured code TTL.
func (s *RedisStore) SaveAuthorizationCode(ctx context.Context, ac *AuthorizationCode) error {
	data, err := json.Marshal(ac)
	if err != nil {
		return fmt.Errorf("marshal authorization code: %w", err)
	}
	if err := s.client.Set(ctx, authorizationCodePrefix+ac.Code, data, s.codeTTL).Err(); err != nil {
		return fmt.Errorf("save authorization code: %w", err)
	}
	return nil
}

// ConsumeAuthorizationCode atomically retrieves and deletes the
// authorization code (GETDEL), enforcing single-use redemption at the token
// endpoint. Returns ErrAuthorizationCodeNotFound if it does not exist, has
// expired, or was already redeemed.
func (s *RedisStore) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	data, err := s.client.GetDel(ctx, authorizationCodePrefix+code).Bytes()
	if err != nil {
		if err == redis.Nil {
			return nil, ErrAuthorizationCodeNotFound
		}
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	var ac AuthorizationCode
	if err := json.Unmarshal(data, &ac); err != nil {
		return nil, fmt.Errorf("unmarshal authorization code: %w", err)
	}
	return &ac, nil
}
