package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/oauth2"
)

type pkceKey struct{}

// WithCodeVerifier returns a new context carrying the PKCE code verifier.
func WithCodeVerifier(ctx context.Context, verifier string) context.Context {
	return context.WithValue(ctx, pkceKey{}, verifier)
}

// CodeVerifierFromContext extracts the PKCE code verifier from the context.
func CodeVerifierFromContext(ctx context.Context) string {
	v, _ := ctx.Value(pkceKey{}).(string)
	return v
}

// GenerateVerifier creates a cryptographically random PKCE code verifier.
func GenerateVerifier() string {
	return oauth2.GenerateVerifier()
}

// S256Challenge computes the S256 code challenge for the given verifier.
// This is needed for providers that don't use the oauth2 library's built-in PKCE
// (e.g. Apple's custom token exchange).
func S256Challenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
