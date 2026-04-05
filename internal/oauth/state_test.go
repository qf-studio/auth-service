package oauth

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testSecret = "test-hmac-secret-32-bytes-long!!"

func TestStateManager_GenerateAndValidate(t *testing.T) {
	sm := NewStateManager(testSecret)
	verifier := "test-code-verifier"

	state, err := sm.Generate(verifier)
	require.NoError(t, err)
	assert.NotEmpty(t, state)
	assert.Contains(t, state, ".", "state should have payload.signature format")

	got, err := sm.Validate(state)
	require.NoError(t, err)
	assert.Equal(t, verifier, got)
}

func TestStateManager_UniqueStates(t *testing.T) {
	sm := NewStateManager(testSecret)

	s1, err := sm.Generate("v1")
	require.NoError(t, err)
	s2, err := sm.Generate("v1")
	require.NoError(t, err)

	assert.NotEqual(t, s1, s2, "states should be unique due to random nonce")
}

func TestStateManager_TamperedSignature(t *testing.T) {
	sm := NewStateManager(testSecret)

	state, err := sm.Generate("verifier")
	require.NoError(t, err)

	// Tamper with the last character of the signature.
	tampered := state[:len(state)-1] + "X"
	_, err = sm.Validate(tampered)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestStateManager_TamperedPayload(t *testing.T) {
	sm := NewStateManager(testSecret)

	state, err := sm.Generate("verifier")
	require.NoError(t, err)

	// Replace first char of payload to tamper.
	tampered := "X" + state[1:]
	_, err = sm.Validate(tampered)
	assert.Error(t, err)
}

func TestStateManager_WrongSecret(t *testing.T) {
	sm1 := NewStateManager("secret-one")
	sm2 := NewStateManager("secret-two")

	state, err := sm1.Generate("verifier")
	require.NoError(t, err)

	_, err = sm2.Validate(state)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature mismatch")
}

func TestStateManager_Expired(t *testing.T) {
	sm := NewStateManager(testSecret)
	// Set clock to 11 minutes in the past so the state expires immediately.
	sm.nowFn = func() time.Time {
		return time.Now().Add(-11 * time.Minute)
	}

	state, err := sm.Generate("verifier")
	require.NoError(t, err)

	// Validate with current time — state should be expired.
	sm.nowFn = time.Now
	_, err = sm.Validate(state)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "expired")
}

func TestStateManager_NotExpiredWithinWindow(t *testing.T) {
	sm := NewStateManager(testSecret)
	// State generated 5 minutes ago — still within 10-minute window.
	sm.nowFn = func() time.Time {
		return time.Now().Add(-5 * time.Minute)
	}

	state, err := sm.Generate("verifier")
	require.NoError(t, err)

	sm.nowFn = time.Now
	got, err := sm.Validate(state)
	require.NoError(t, err)
	assert.Equal(t, "verifier", got)
}

func TestStateManager_InvalidFormat(t *testing.T) {
	sm := NewStateManager(testSecret)

	tests := []struct {
		name  string
		state string
	}{
		{"empty", ""},
		{"no dot", "nodot"},
		{"just a dot", "."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := sm.Validate(tt.state)
			assert.Error(t, err)
		})
	}
}

func TestStateManager_PreservesVerifier(t *testing.T) {
	sm := NewStateManager(testSecret)

	verifiers := []string{
		"",
		"short",
		"a-longer-verifier-with-special-chars_~.",
		GenerateVerifier(),
	}

	for _, v := range verifiers {
		state, err := sm.Generate(v)
		require.NoError(t, err)

		got, err := sm.Validate(state)
		require.NoError(t, err)
		assert.Equal(t, v, got)
	}
}
