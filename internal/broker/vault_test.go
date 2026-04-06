package broker

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewVault(t *testing.T) {
	t.Run("valid secret", func(t *testing.T) {
		v, err := NewVault("test-secret-key")
		require.NoError(t, err)
		assert.NotNil(t, v)
	})

	t.Run("empty secret returns error", func(t *testing.T) {
		v, err := NewVault("")
		assert.Error(t, err)
		assert.Nil(t, v)
		assert.Contains(t, err.Error(), "must not be empty")
	})
}

func TestVault_EncryptDecrypt(t *testing.T) {
	v, err := NewVault("test-secret-for-encryption")
	require.NoError(t, err)

	tests := []struct {
		name      string
		plaintext []byte
	}{
		{
			name:      "simple text",
			plaintext: []byte("my-api-key-12345"),
		},
		{
			name:      "empty payload",
			plaintext: nil, // GCM Open returns nil for empty plaintext.
		},
		{
			name:      "binary data",
			plaintext: []byte{0x00, 0x01, 0xFF, 0xFE, 0x80},
		},
		{
			name:      "large payload",
			plaintext: bytes.Repeat([]byte("A"), 4096),
		},
		{
			name:      "json credential",
			plaintext: []byte(`{"token":"ghp_abc123","endpoint":"https://api.example.com"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := v.Encrypt(tt.plaintext)
			require.NoError(t, err)
			assert.NotEmpty(t, ciphertext)

			// Ciphertext must differ from plaintext.
			assert.NotEqual(t, tt.plaintext, ciphertext)

			decrypted, err := v.Decrypt(ciphertext)
			require.NoError(t, err)
			assert.Equal(t, tt.plaintext, decrypted)
		})
	}
}

func TestVault_EncryptProducesUniqueCiphertexts(t *testing.T) {
	v, err := NewVault("unique-nonce-secret")
	require.NoError(t, err)

	plaintext := []byte("same-data")
	ct1, err := v.Encrypt(plaintext)
	require.NoError(t, err)

	ct2, err := v.Encrypt(plaintext)
	require.NoError(t, err)

	// Each encryption must use a unique nonce, producing different ciphertext.
	assert.NotEqual(t, ct1, ct2)
}

func TestVault_DecryptWithWrongKey(t *testing.T) {
	v1, err := NewVault("key-one")
	require.NoError(t, err)

	v2, err := NewVault("key-two")
	require.NoError(t, err)

	ciphertext, err := v1.Encrypt([]byte("sensitive-data"))
	require.NoError(t, err)

	_, err = v2.Decrypt(ciphertext)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "decrypt")
}

func TestVault_DecryptTruncatedCiphertext(t *testing.T) {
	v, err := NewVault("truncation-test")
	require.NoError(t, err)

	// Too short: less than nonce + GCM tag overhead.
	_, err = v.Decrypt([]byte("short"))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ciphertext too short")
}

func TestVault_DecryptCorruptedCiphertext(t *testing.T) {
	v, err := NewVault("corruption-test")
	require.NoError(t, err)

	ciphertext, err := v.Encrypt([]byte("original-data"))
	require.NoError(t, err)

	// Flip a byte in the encrypted portion (after the nonce).
	corrupted := make([]byte, len(ciphertext))
	copy(corrupted, ciphertext)
	corrupted[gcmNonceSize+1] ^= 0xFF

	_, err = v.Decrypt(corrupted)
	assert.Error(t, err)
}

func TestDeriveKey(t *testing.T) {
	key := deriveKey("test-secret")
	assert.Len(t, key, aesKeySize)

	// Same input must produce same key.
	key2 := deriveKey("test-secret")
	assert.Equal(t, key, key2)

	// Different input must produce different key.
	key3 := deriveKey("different-secret")
	assert.NotEqual(t, key, key3)
}
