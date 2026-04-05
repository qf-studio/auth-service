package oauth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCE(t *testing.T) {
	pair, err := GeneratePKCE()
	require.NoError(t, err)

	// Verifier should be base64url-encoded 32 bytes = 43 characters.
	assert.Len(t, pair.Verifier, 43)
	// Challenge should be base64url-encoded SHA-256 = 43 characters.
	assert.Len(t, pair.Challenge, 43)
	// Verifier and challenge must differ.
	assert.NotEqual(t, pair.Verifier, pair.Challenge)
}

func TestGeneratePKCE_Deterministic(t *testing.T) {
	// Verify that s256Challenge is deterministic.
	verifier := "test-verifier-1234567890"
	c1 := s256Challenge(verifier)
	c2 := s256Challenge(verifier)
	assert.Equal(t, c1, c2)
}

func TestGeneratePKCE_Uniqueness(t *testing.T) {
	pair1, err := GeneratePKCE()
	require.NoError(t, err)
	pair2, err := GeneratePKCE()
	require.NoError(t, err)

	assert.NotEqual(t, pair1.Verifier, pair2.Verifier)
	assert.NotEqual(t, pair1.Challenge, pair2.Challenge)
}
