package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateVerifier(t *testing.T) {
	v1 := GenerateVerifier()
	v2 := GenerateVerifier()

	assert.NotEmpty(t, v1)
	assert.NotEmpty(t, v2)
	assert.NotEqual(t, v1, v2, "verifiers should be unique")
	// RFC 7636: verifier must be 43-128 characters
	assert.GreaterOrEqual(t, len(v1), 43)
	assert.LessOrEqual(t, len(v1), 128)
}

func TestS256Challenge(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	challenge := S256Challenge(verifier)

	// Manually compute expected challenge.
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, expected, challenge)
}

func TestS256Challenge_Deterministic(t *testing.T) {
	verifier := GenerateVerifier()

	c1 := S256Challenge(verifier)
	c2 := S256Challenge(verifier)
	assert.Equal(t, c1, c2)
}

func TestCodeVerifierContext(t *testing.T) {
	ctx := context.Background()

	// No verifier set.
	assert.Empty(t, CodeVerifierFromContext(ctx))

	// Set verifier.
	verifier := "test-verifier-value"
	ctx = WithCodeVerifier(ctx, verifier)
	assert.Equal(t, verifier, CodeVerifierFromContext(ctx))
}

func TestCodeVerifierContext_EmptyString(t *testing.T) {
	ctx := WithCodeVerifier(context.Background(), "")
	assert.Empty(t, CodeVerifierFromContext(ctx))
}

func TestGenerateVerifier_URLSafe(t *testing.T) {
	// Generate many verifiers and check they contain only URL-safe characters.
	for i := 0; i < 100; i++ {
		v := GenerateVerifier()
		_, err := base64.RawURLEncoding.DecodeString(v)
		require.NoError(t, err, "verifier should be valid base64url")
	}
}
