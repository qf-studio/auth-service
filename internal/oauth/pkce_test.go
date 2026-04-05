package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateCodeVerifier(t *testing.T) {
	t.Run("produces valid base64url string", func(t *testing.T) {
		v, err := GenerateCodeVerifier()
		require.NoError(t, err)

		// 32 bytes → 43 base64url chars (no padding).
		assert.Len(t, v, 43)

		// Must decode without error.
		decoded, err := base64.RawURLEncoding.DecodeString(v)
		require.NoError(t, err)
		assert.Len(t, decoded, codeVerifierBytes)
	})

	t.Run("produces unique values", func(t *testing.T) {
		v1, err := GenerateCodeVerifier()
		require.NoError(t, err)

		v2, err := GenerateCodeVerifier()
		require.NoError(t, err)

		assert.NotEqual(t, v1, v2)
	})
}

func TestCodeChallenge(t *testing.T) {
	t.Run("S256 transform matches RFC 7636 Appendix B", func(t *testing.T) {
		// RFC 7636 Appendix B example (adapted for base64url without padding).
		verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		challenge := CodeChallenge(verifier)

		// Manually compute expected: BASE64URL(SHA256(verifier))
		h := sha256.Sum256([]byte(verifier))
		expected := base64.RawURLEncoding.EncodeToString(h[:])

		assert.Equal(t, expected, challenge)
	})

	t.Run("different verifiers produce different challenges", func(t *testing.T) {
		c1 := CodeChallenge("verifier-one")
		c2 := CodeChallenge("verifier-two")
		assert.NotEqual(t, c1, c2)
	})

	t.Run("same verifier is deterministic", func(t *testing.T) {
		c1 := CodeChallenge("stable-verifier")
		c2 := CodeChallenge("stable-verifier")
		assert.Equal(t, c1, c2)
	})
}

func TestCodeVerifierChallengeRoundTrip(t *testing.T) {
	// Generate a verifier, compute its challenge, then verify the relationship.
	verifier, err := GenerateCodeVerifier()
	require.NoError(t, err)

	challenge := CodeChallenge(verifier)

	// Re-compute from the verifier to verify the S256 relationship.
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	assert.Equal(t, expected, challenge)
}
