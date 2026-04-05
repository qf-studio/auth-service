package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const stateMaxAge = 10 * time.Minute

// statePayload is the internal structure embedded in the signed state token.
type statePayload struct {
	Nonce    string `json:"n"`
	Exp      int64  `json:"e"`
	Verifier string `json:"v"`
}

// StateManager generates and validates signed, time-limited OAuth state parameters
// with embedded PKCE verifiers for CSRF protection.
type StateManager struct {
	secret []byte
	nowFn  func() time.Time // injectable for testing
}

// NewStateManager creates a StateManager using the given HMAC secret.
func NewStateManager(secret string) *StateManager {
	return &StateManager{
		secret: []byte(secret),
		nowFn:  time.Now,
	}
}

// Generate creates a signed state token containing a random nonce, expiration,
// and the PKCE code verifier.
func (sm *StateManager) Generate(verifier string) (string, error) {
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("generate nonce: %w", err)
	}

	payload := statePayload{
		Nonce:    base64.RawURLEncoding.EncodeToString(nonce),
		Exp:      sm.nowFn().Add(stateMaxAge).Unix(),
		Verifier: verifier,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}

	encoded := base64.RawURLEncoding.EncodeToString(data)
	sig := sm.sign(encoded)

	return encoded + "." + sig, nil
}

// Validate checks the signature and expiration of a state token and returns
// the embedded PKCE code verifier.
func (sm *StateManager) Validate(state string) (verifier string, err error) {
	parts := strings.SplitN(state, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("invalid state format")
	}

	encoded, sig := parts[0], parts[1]
	if !sm.verify(encoded, sig) {
		return "", errors.New("state signature mismatch")
	}

	data, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", fmt.Errorf("decode state: %w", err)
	}

	var payload statePayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return "", fmt.Errorf("unmarshal state: %w", err)
	}

	if sm.nowFn().Unix() > payload.Exp {
		return "", errors.New("state expired")
	}

	return payload.Verifier, nil
}

func (sm *StateManager) sign(data string) string {
	mac := hmac.New(sha256.New, sm.secret)
	_, _ = mac.Write([]byte(data))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (sm *StateManager) verify(data, sig string) bool {
	expected := sm.sign(data)
	return hmac.Equal([]byte(expected), []byte(sig))
}
