// Package webhook provides webhook registration, HMAC-SHA256 payload signing,
// and async event delivery with retry logic.
package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

// Sign computes an HMAC-SHA256 signature of payload using the given secret.
// The result is the hex-encoded digest prefixed with "sha256=", matching the
// X-Signature-256 header format used by GitHub-style webhooks.
func Sign(secret string, payload []byte) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(payload) // hmac.Write never returns an error
	return "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

// Verify checks that the given signature matches the expected HMAC-SHA256 of payload.
// Uses constant-time comparison to prevent timing attacks.
func Verify(secret string, payload []byte, signature string) bool {
	expected := Sign(secret, payload)
	return hmac.Equal([]byte(expected), []byte(signature))
}
