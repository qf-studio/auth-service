// Package broker implements the credential broker that allows agents to obtain
// short-lived proxy tokens for target services without ever seeing the real
// credentials. The vault sub-component handles AES-256-GCM encryption and
// decryption of credential payloads at rest.
package broker

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
)

const (
	// aesKeySize is the required key length for AES-256.
	aesKeySize = 32

	// gcmNonceSize is the standard nonce size for AES-GCM (12 bytes).
	gcmNonceSize = 12
)

// Vault provides AES-256-GCM encryption and decryption of credential payloads.
// The encryption key is derived from a system secret via SHA-256.
type Vault struct {
	aead cipher.AEAD
}

// NewVault creates a Vault with an encryption key derived from the given system
// secret. The secret is hashed with SHA-256 to produce a 32-byte AES-256 key.
func NewVault(systemSecret string) (*Vault, error) {
	if systemSecret == "" {
		return nil, errors.New("broker: vault secret must not be empty")
	}

	key := deriveKey(systemSecret)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("broker: create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("broker: create GCM: %w", err)
	}

	return &Vault{aead: aead}, nil
}

// Encrypt encrypts plaintext using AES-256-GCM with a random nonce.
// The returned ciphertext has the nonce prepended: nonce || ciphertext || tag.
func (v *Vault) Encrypt(plaintext []byte) ([]byte, error) {
	nonce := make([]byte, gcmNonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("broker: generate nonce: %w", err)
	}

	// Seal appends the ciphertext+tag to the nonce slice.
	ciphertext := v.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts ciphertext that was produced by Encrypt.
// It expects the nonce to be prepended to the ciphertext.
func (v *Vault) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < gcmNonceSize+v.aead.Overhead() {
		return nil, errors.New("broker: ciphertext too short")
	}

	nonce := ciphertext[:gcmNonceSize]
	encrypted := ciphertext[gcmNonceSize:]

	plaintext, err := v.aead.Open(nil, nonce, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("broker: decrypt: %w", err)
	}

	return plaintext, nil
}

// deriveKey produces a 32-byte AES-256 key from an arbitrary-length secret.
func deriveKey(secret string) []byte {
	h := sha256.Sum256([]byte(secret))
	return h[:]
}
