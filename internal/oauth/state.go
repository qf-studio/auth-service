package oauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"
)

// StateGenerator generates and validates OAuth state parameters for CSRF protection.
type StateGenerator interface {
	// Generate creates a new signed, time-limited state token.
	Generate() (string, error)
	// Validate checks that a state token is correctly signed and not expired.
	Validate(state string) error
}

// HMACStateGenerator produces HMAC-signed state tokens with embedded timestamps.
// Format: base64url(timestamp_bytes || random_bytes || hmac_signature)
type HMACStateGenerator struct {
	secret []byte
	ttl    time.Duration
	nowFn  func() time.Time
}

// NewHMACStateGenerator creates a new HMAC-based state generator.
func NewHMACStateGenerator(secret []byte, ttl time.Duration) *HMACStateGenerator {
	return &HMACStateGenerator{
		secret: secret,
		ttl:    ttl,
		nowFn:  time.Now,
	}
}

const (
	stateTimestampLen = 8  // int64 unix seconds
	stateRandomLen    = 16 // 128 bits of randomness
	stateHMACLen      = 32 // SHA-256
	statePayloadLen   = stateTimestampLen + stateRandomLen
	stateTotalLen     = statePayloadLen + stateHMACLen
)

// Generate creates a new signed state token.
func (g *HMACStateGenerator) Generate() (string, error) {
	payload := make([]byte, statePayloadLen)
	binary.BigEndian.PutUint64(payload[:stateTimestampLen], uint64(g.nowFn().Unix()))

	if _, err := rand.Read(payload[stateTimestampLen:]); err != nil {
		return "", fmt.Errorf("generate random bytes: %w", err)
	}

	mac := hmac.New(sha256.New, g.secret)
	_, _ = mac.Write(payload)
	sig := mac.Sum(nil)

	token := make([]byte, stateTotalLen)
	copy(token, payload)
	copy(token[statePayloadLen:], sig)

	return base64.RawURLEncoding.EncodeToString(token), nil
}

// Validate checks that a state token is correctly signed and not expired.
func (g *HMACStateGenerator) Validate(state string) error {
	raw, err := base64.RawURLEncoding.DecodeString(state)
	if err != nil {
		return fmt.Errorf("decode state: %w", err)
	}

	if len(raw) != stateTotalLen {
		return fmt.Errorf("invalid state length")
	}

	payload := raw[:statePayloadLen]
	sig := raw[statePayloadLen:]

	mac := hmac.New(sha256.New, g.secret)
	_, _ = mac.Write(payload)
	expected := mac.Sum(nil)

	if !hmac.Equal(sig, expected) {
		return fmt.Errorf("invalid state signature")
	}

	ts := int64(binary.BigEndian.Uint64(payload[:stateTimestampLen]))
	created := time.Unix(ts, 0)
	if g.nowFn().Sub(created) > g.ttl {
		return fmt.Errorf("state token expired")
	}

	return nil
}
