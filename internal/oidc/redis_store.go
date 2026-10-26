package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

	// usedCodePrefix namespaces used-code records, keyed by the SHA-256 of the
	// authorization code (the raw code is never used as a key here).
	usedCodePrefix = "oidc_code_used:"

	// defaultUsedCodeTTL is how long a used-code record is kept. It must cover
	// the access-token lifetime (see WithUsedCodeTTL), with a 15 minute floor.
	defaultUsedCodeTTL = 15 * time.Minute

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
	usedCodeTTL  time.Duration
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

// WithUsedCodeTTL overrides the lifetime of used-code records. Values below
// the 15 minute default are ignored: the record must outlive the access
// token issued from the code, so callers pass the access-token TTL.
func WithUsedCodeTTL(d time.Duration) RedisStoreOption {
	return func(s *RedisStore) {
		if d > defaultUsedCodeTTL {
			s.usedCodeTTL = d
		}
	}
}

// NewRedisStore creates a new Redis-backed OIDC provider store.
func NewRedisStore(client redis.Cmdable, opts ...RedisStoreOption) *RedisStore {
	s := &RedisStore{
		client:       client,
		challengeTTL: defaultChallengeTTL,
		codeTTL:      defaultCodeTTL,
		usedCodeTTL:  defaultUsedCodeTTL,
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

// consumeCodeScript atomically reads and deletes the authorization code and
// writes the used-code record. The record is only written when the code
// existed, so presenting arbitrary strings cannot create records.
// KEYS[1]=code key, KEYS[2]=used-code key, ARGV[1]=used-code TTL in ms.
var consumeCodeScript = redis.NewScript(`
local v = redis.call('GETDEL', KEYS[1])
if not v then
  return false
end
redis.call('HSET', KEYS[2], 'used', '1')
redis.call('PEXPIRE', KEYS[2], ARGV[1])
return v
`)

// recordIssuanceScript stores the issued-token identifiers on the used-code
// record and returns 1 if it was flagged replayed, 0 if not, -1 if the record
// does not exist. It runs atomically with markReplayedScript, so exactly one
// of the two observes the other. KEYS[1]=used-code key.
var recordIssuanceScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return -1
end
redis.call('HSET', KEYS[1], 'issued', '1', 'jti', ARGV[1], 'exp', ARGV[2], 'fid', ARGV[3])
if redis.call('HEXISTS', KEYS[1], 'replayed') == 1 then
  return 1
end
return 0
`)

// markReplayedScript flags the used-code record replayed and returns
// {issued, jti, exp, fid}, or false if there is no record. KEYS[1]=used-code key.
var markReplayedScript = redis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return false
end
redis.call('HSET', KEYS[1], 'replayed', '1')
return redis.call('HMGET', KEYS[1], 'issued', 'jti', 'exp', 'fid')
`)

// usedCodeKey is the used-code record key for code: the SHA-256 of the code,
// hex-encoded.
func usedCodeKey(code string) string {
	sum := sha256.Sum256([]byte(code))
	return usedCodePrefix + hex.EncodeToString(sum[:])
}

// ConsumeAuthorizationCode atomically retrieves and deletes the
// authorization code (GETDEL), enforcing single-use redemption at the token
// endpoint, and records the redemption in a used-code record so a second
// presentation can be recognized (GH-542). Returns
// ErrAuthorizationCodeNotFound if it does not exist, has expired, or was
// already redeemed.
func (s *RedisStore) ConsumeAuthorizationCode(ctx context.Context, code string) (*AuthorizationCode, error) {
	res, err := consumeCodeScript.Run(ctx, s.client,
		[]string{authorizationCodePrefix + code, usedCodeKey(code)},
		s.usedCodeTTL.Milliseconds(),
	).Text()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrAuthorizationCodeNotFound
		}
		return nil, fmt.Errorf("consume authorization code: %w", err)
	}
	var ac AuthorizationCode
	if err := json.Unmarshal([]byte(res), &ac); err != nil {
		return nil, fmt.Errorf("unmarshal authorization code: %w", err)
	}
	return &ac, nil
}

// RecordCodeIssuance stores the identifiers of the tokens issued from code on
// its used-code record. It reports whether the code was presented again before
// this call, in which case the caller must revoke those tokens.
func (s *RedisStore) RecordCodeIssuance(ctx context.Context, code string, iss CodeIssuance) (bool, error) {
	n, err := recordIssuanceScript.Run(ctx, s.client, []string{usedCodeKey(code)},
		iss.AccessTokenID, iss.AccessTokenExpiresAt.Unix(), iss.RefreshFamilyID,
	).Int()
	if err != nil {
		return false, fmt.Errorf("record code issuance: %w", err)
	}
	switch n {
	case -1:
		return false, ErrUsedCodeNotFound
	case 0:
		return false, nil
	default:
		return true, nil
	}
}

// MarkCodeReplayed flags the used-code record for code as replayed and returns
// the tokens issued from it, or nil if they have not been recorded yet.
func (s *RedisStore) MarkCodeReplayed(ctx context.Context, code string) (*CodeIssuance, error) {
	res, err := markReplayedScript.Run(ctx, s.client, []string{usedCodeKey(code)}).Slice()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, ErrUsedCodeNotFound
		}
		return nil, fmt.Errorf("mark code replayed: %w", err)
	}
	if len(res) != 4 {
		return nil, fmt.Errorf("mark code replayed: unexpected reply of %d fields", len(res))
	}
	if res[0] == nil {
		return nil, nil // first redemption has not recorded issuance yet
	}
	iss := &CodeIssuance{}
	iss.AccessTokenID, _ = res[1].(string)
	if exp, _ := res[2].(string); exp != "" {
		secs, err := strconv.ParseInt(exp, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("mark code replayed: parse exp: %w", err)
		}
		iss.AccessTokenExpiresAt = time.Unix(secs, 0)
	}
	iss.RefreshFamilyID, _ = res[3].(string)
	return iss, nil
}
