// Package secretbox protects secrets that live in the database: one-time
// tokens are stored as SHA-256 digests (Digest), and secrets that must be read
// back, such as TOTP seeds and webhook signing keys, are sealed with
// AES-256-GCM (Box).
package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const (
	// KeySize is the required length of the data-encryption key (AES-256).
	KeySize = 32

	// versionPrefix marks a sealed value. Anything without it is treated as
	// legacy plaintext, so the format can evolve (v2:...) without a flag day.
	versionPrefix = "v1:"
)

// ErrKeyRequired is returned when a sealed value is read but no key is configured.
var ErrKeyRequired = errors.New("secretbox: value is encrypted but DATA_ENCRYPTION_KEY is not set")

// Digest returns the lowercase hex SHA-256 of a one-time token. Tokens are
// 256-bit random values, so a plain digest (not a slow hash) is sufficient and
// keeps lookups indexable; it is the same scheme as API keys (migration 000019).
func Digest(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// Box encrypts and decrypts secrets. A nil *Box is valid and passes values
// through unchanged: that is the documented behavior when no key is set.
type Box struct {
	aead cipher.AEAD
}

// New returns a Box for a 32-byte key.
func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("secretbox: key must be %d bytes, got %d", KeySize, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secretbox: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: new gcm: %w", err)
	}
	return &Box{aead: aead}, nil
}

// ParseKey decodes a base64 (standard or URL-safe, padded or not) 32-byte key.
func ParseKey(b64 string) ([]byte, error) {
	b64 = strings.TrimSpace(b64)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if key, err := enc.DecodeString(b64); err == nil {
			if len(key) != KeySize {
				return nil, fmt.Errorf("secretbox: key must decode to %d bytes, got %d", KeySize, len(key))
			}
			return key, nil
		}
	}
	return nil, errors.New("secretbox: key is not valid base64")
}

// Enabled reports whether the box actually encrypts.
func (b *Box) Enabled() bool { return b != nil }

// IsEncrypted reports whether s is in the sealed format.
func IsEncrypted(s string) bool { return strings.HasPrefix(s, versionPrefix) }

// Encrypt returns "v1:<base64 nonce>:<base64 ciphertext>". With a nil Box the
// plaintext is returned unchanged. Already-sealed input is returned as is, so
// callers can write a value they read back without double-encrypting it.
func (b *Box) Encrypt(plaintext string) (string, error) {
	if b == nil || IsEncrypted(plaintext) {
		return plaintext, nil
	}
	nonce := make([]byte, b.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("secretbox: generate nonce: %w", err)
	}
	ct := b.aead.Seal(nil, nonce, []byte(plaintext), nil)
	return versionPrefix + base64.StdEncoding.EncodeToString(nonce) + ":" + base64.StdEncoding.EncodeToString(ct), nil
}

// Decrypt reverses Encrypt. Values without the "v1:" prefix are legacy
// plaintext and are returned unchanged. A sealed value with no key configured
// is an error rather than being handed to callers as if it were the secret.
func (b *Box) Decrypt(value string) (string, error) {
	if !IsEncrypted(value) {
		return value, nil
	}
	if b == nil {
		return "", ErrKeyRequired
	}
	parts := strings.Split(strings.TrimPrefix(value, versionPrefix), ":")
	if len(parts) != 2 {
		return "", errors.New("secretbox: malformed ciphertext")
	}
	nonce, err := base64.StdEncoding.DecodeString(parts[0])
	if err != nil || len(nonce) != b.aead.NonceSize() {
		return "", errors.New("secretbox: malformed nonce")
	}
	ct, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return "", errors.New("secretbox: malformed ciphertext")
	}
	pt, err := b.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return "", fmt.Errorf("secretbox: decrypt: %w", err)
	}
	return string(pt), nil
}
