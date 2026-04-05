package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const (
	stateNonceBytes = 16
	stateTTL        = 10 * time.Minute
)

// StateStore abstracts storage of OAuth state tokens (typically Redis with TTL).
type StateStore interface {
	StoreOAuthState(ctx context.Context, key string, data []byte, ttl time.Duration) error
	ConsumeOAuthState(ctx context.Context, key string) ([]byte, error)
}

// statePayload is the internal structure signed and stored for each auth initiation.
type statePayload struct {
	Nonce        string                `json:"n"`
	Provider     string                `json:"p"`
	CodeVerifier string                `json:"cv"`
	CreatedAt    int64                 `json:"t"`
}

// StateManager handles creation and validation of signed, time-limited state tokens.
type StateManager struct {
	secret []byte
	store  StateStore
}

// NewStateManager creates a StateManager with the given HMAC secret and backing store.
func NewStateManager(secret string, store StateStore) *StateManager {
	return &StateManager{
		secret: []byte(secret),
		store:  store,
	}
}

// GenerateState creates a signed state token containing CSRF nonce and PKCE verifier.
// It stores the full payload in the backing store and returns the state string (nonce.signature)
// that should be passed as the OAuth state parameter.
func (m *StateManager) GenerateState(ctx context.Context, provider string, codeVerifier string) (string, error) {
	nonce := make([]byte, stateNonceBytes)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate state nonce: %w", err)
	}
	nonceStr := base64.RawURLEncoding.EncodeToString(nonce)

	payload := statePayload{
		Nonce:        nonceStr,
		Provider:     provider,
		CodeVerifier: codeVerifier,
		CreatedAt:    time.Now().Unix(),
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal state payload: %w", err)
	}

	sig := m.sign(nonceStr)
	stateToken := nonceStr + "." + sig

	if err := m.store.StoreOAuthState(ctx, stateToken, data, stateTTL); err != nil {
		return "", fmt.Errorf("store oauth state: %w", err)
	}

	return stateToken, nil
}

// ValidateState consumes a state token from the store, verifies the HMAC signature,
// and checks expiry. Returns the provider name and code verifier on success.
func (m *StateManager) ValidateState(ctx context.Context, stateToken string) (provider, codeVerifier string, err error) {
	// Split nonce.signature
	dotIdx := -1
	for i := range stateToken {
		if stateToken[i] == '.' {
			dotIdx = i
			break
		}
	}
	if dotIdx < 0 {
		return "", "", fmt.Errorf("malformed state token")
	}

	nonceStr := stateToken[:dotIdx]
	sig := stateToken[dotIdx+1:]

	// Verify HMAC signature.
	expectedSig := m.sign(nonceStr)
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", "", fmt.Errorf("invalid state signature")
	}

	// Consume from store (atomic get-and-delete prevents replay).
	data, err := m.store.ConsumeOAuthState(ctx, stateToken)
	if err != nil {
		return "", "", fmt.Errorf("consume state: %w", err)
	}

	var payload statePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", "", fmt.Errorf("unmarshal state payload: %w", err)
	}

	// Verify nonce matches.
	if payload.Nonce != nonceStr {
		return "", "", fmt.Errorf("state nonce mismatch")
	}

	// Check expiry.
	if time.Since(time.Unix(payload.CreatedAt, 0)) > stateTTL {
		return "", "", fmt.Errorf("state token expired")
	}

	return payload.Provider, payload.CodeVerifier, nil
}

// sign computes the HMAC-SHA256 of the given data and returns it as base64url.
func (m *StateManager) sign(data string) string {
	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
