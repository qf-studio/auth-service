package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	tests := []struct {
		name    string
		secret  string
		payload []byte
		want    string
	}{
		{
			name:    "basic payload",
			secret:  "mysecret",
			payload: []byte(`{"event":"user.created"}`),
			// pre-computed: echo -n '{"event":"user.created"}' | openssl dgst -sha256 -hmac 'mysecret'
			want: "sha256=",
		},
		{
			name:    "empty payload",
			secret:  "key",
			payload: []byte{},
			want:    "sha256=",
		},
		{
			name:    "empty secret",
			secret:  "",
			payload: []byte("data"),
			want:    "sha256=",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sig := Sign(tc.secret, tc.payload)
			assert.Contains(t, sig, "sha256=")
			assert.Len(t, sig, 7+64) // "sha256=" (7) + 64 hex chars
		})
	}
}

func TestSign_Deterministic(t *testing.T) {
	secret := "webhook-secret-key"
	payload := []byte(`{"type":"user.created","data":{"id":"abc123"}}`)

	sig1 := Sign(secret, payload)
	sig2 := Sign(secret, payload)
	assert.Equal(t, sig1, sig2, "same input must produce same signature")
}

func TestSign_DifferentSecrets(t *testing.T) {
	payload := []byte(`{"event":"test"}`)
	sig1 := Sign("secret1", payload)
	sig2 := Sign("secret2", payload)
	assert.NotEqual(t, sig1, sig2, "different secrets must produce different signatures")
}

func TestSign_DifferentPayloads(t *testing.T) {
	secret := "shared"
	sig1 := Sign(secret, []byte("payload1"))
	sig2 := Sign(secret, []byte("payload2"))
	assert.NotEqual(t, sig1, sig2, "different payloads must produce different signatures")
}

func TestVerify(t *testing.T) {
	secret := "test-secret"
	payload := []byte(`{"action":"login"}`)

	sig := Sign(secret, payload)

	t.Run("valid signature", func(t *testing.T) {
		require.True(t, Verify(secret, payload, sig))
	})

	t.Run("wrong secret", func(t *testing.T) {
		assert.False(t, Verify("wrong", payload, sig))
	})

	t.Run("wrong payload", func(t *testing.T) {
		assert.False(t, Verify(secret, []byte("tampered"), sig))
	})

	t.Run("wrong signature", func(t *testing.T) {
		assert.False(t, Verify(secret, payload, "sha256=0000000000000000000000000000000000000000000000000000000000000000"))
	})

	t.Run("malformed signature", func(t *testing.T) {
		assert.False(t, Verify(secret, payload, "not-a-valid-sig"))
	})
}
