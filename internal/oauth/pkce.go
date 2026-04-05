package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
)

const (
	// pkceVerifierBytes produces a 43-character base64url verifier (RFC 7636 minimum is 43).
	pkceVerifierBytes = 32
)

// PKCEPair holds a code_verifier and its corresponding S256 code_challenge.
type PKCEPair struct {
	Verifier  string
	Challenge string
}

// GeneratePKCE creates a new PKCE code_verifier / code_challenge pair using S256.
func GeneratePKCE() (*PKCEPair, error) {
	b := make([]byte, pkceVerifierBytes)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	verifier := base64.RawURLEncoding.EncodeToString(b)
	return &PKCEPair{
		Verifier:  verifier,
		Challenge: s256Challenge(verifier),
	}, nil
}

// s256Challenge computes the S256 PKCE challenge from a verifier.
func s256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
