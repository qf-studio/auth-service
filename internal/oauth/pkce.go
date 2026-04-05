package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

// PKCE implements RFC 7636 Proof Key for Code Exchange (S256 method).

const (
	// codeVerifierBytes is the number of random bytes for the verifier (32 bytes → 43 base64url chars).
	// RFC 7636 requires 43-128 characters; 32 bytes yields 43 characters.
	codeVerifierBytes = 32
)

// GenerateCodeVerifier creates a cryptographically random code_verifier
// per RFC 7636 Section 4.1.
func GenerateCodeVerifier() (string, error) {
	buf := make([]byte, codeVerifierBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// CodeChallenge computes the S256 code_challenge from a code_verifier
// per RFC 7636 Section 4.2: BASE64URL(SHA256(code_verifier)).
func CodeChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
