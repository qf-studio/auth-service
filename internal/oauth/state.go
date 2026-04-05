package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// StateManager handles creation and validation of HMAC-signed, time-limited
// OAuth state parameters backed by Redis for one-time consumption.
type StateManager struct {
	rdb        redis.Cmdable
	hmacSecret []byte
	ttl        time.Duration
	nowFunc    func() time.Time // injectable clock for testing
}

// NewStateManager creates a state manager. hmacSecret must be non-empty.
func NewStateManager(rdb redis.Cmdable, hmacSecret []byte, ttl time.Duration) *StateManager {
	return &StateManager{
		rdb:        rdb,
		hmacSecret: hmacSecret,
		ttl:        ttl,
		nowFunc:    time.Now,
	}
}

// statePayload is the JSON structure stored in Redis and signed by HMAC.
type statePayload struct {
	Nonce     string `json:"n"`
	Provider  string `json:"p"`
	Timestamp int64  `json:"t"`
}

const (
	stateNonceBytes = 16
	redisKeyPrefix  = "oauth:state:"
)

// Generate creates a new state token for the given provider. It stores the
// state in Redis with a TTL and returns the HMAC-signed, base64url-encoded token.
func (sm *StateManager) Generate(ctx context.Context, provider string) (string, error) {
	nonceBuf := make([]byte, stateNonceBytes)
	if _, err := rand.Read(nonceBuf); err != nil {
		return "", fmt.Errorf("generate state nonce: %w", err)
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBuf)

	payload := statePayload{
		Nonce:     nonce,
		Provider:  provider,
		Timestamp: sm.nowFunc().Unix(),
	}

	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal state payload: %w", err)
	}

	sig := sm.sign(payloadJSON)

	// token = base64url(payload) + "." + base64url(sig)
	token := base64.RawURLEncoding.EncodeToString(payloadJSON) +
		"." +
		base64.RawURLEncoding.EncodeToString(sig)

	// Store in Redis for one-time consumption.
	key := redisKeyPrefix + nonce
	if err := sm.rdb.Set(ctx, key, provider, sm.ttl).Err(); err != nil {
		return "", fmt.Errorf("store state in redis: %w", err)
	}

	return token, nil
}

// Validate verifies the state token's HMAC signature, checks TTL, ensures it
// hasn't been consumed, and deletes it from Redis (one-time use). Returns the
// provider name on success.
func (sm *StateManager) Validate(ctx context.Context, token string) (string, error) {
	payloadB64, sigB64, ok := splitToken(token)
	if !ok {
		return "", errors.New("invalid state token format")
	}

	payloadJSON, err := base64.RawURLEncoding.DecodeString(payloadB64)
	if err != nil {
		return "", errors.New("invalid state token encoding")
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(sigB64)
	if err != nil {
		return "", errors.New("invalid state signature encoding")
	}

	// Verify HMAC.
	expected := sm.sign(payloadJSON)
	if !hmac.Equal(sigBytes, expected) {
		return "", errors.New("state token signature mismatch")
	}

	var payload statePayload
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return "", errors.New("invalid state token payload")
	}

	// Check time-based expiry.
	age := sm.nowFunc().Sub(time.Unix(payload.Timestamp, 0))
	if age > sm.ttl || age < 0 {
		return "", errors.New("state token expired")
	}

	// One-time consumption: delete from Redis.
	key := redisKeyPrefix + payload.Nonce
	deleted, err := sm.rdb.Del(ctx, key).Result()
	if err != nil {
		return "", fmt.Errorf("consume state from redis: %w", err)
	}
	if deleted == 0 {
		return "", errors.New("state token already consumed or not found")
	}

	return payload.Provider, nil
}

func (sm *StateManager) sign(data []byte) []byte {
	mac := hmac.New(sha256.New, sm.hmacSecret)
	_, _ = mac.Write(data)
	return mac.Sum(nil)
}

// splitToken splits "a.b" into ("a", "b", true). Returns false if no dot.
func splitToken(token string) (string, string, bool) {
	for i := len(token) - 1; i >= 0; i-- {
		if token[i] == '.' {
			return token[:i], token[i+1:], true
		}
	}
	return "", "", false
}
