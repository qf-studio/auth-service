// Package password provides Argon2id password hashing and verification
// per NIST SP 800-63-4 requirements with optional HMAC pepper support.
package password

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters per project security spec.
const (
	// argonMemory is 19 MiB expressed in KiB (1 KiB = 1024 bytes).
	argonMemory = 19 * 1024 // 19456 KiB

	// argonTime is the number of iterations.
	argonTime = 2

	// argonThreads is the degree of parallelism.
	argonThreads = 1

	// saltLen is 128 bits (16 bytes).
	saltLen = 16

	// keyLen is the output hash length in bytes.
	keyLen = 32
)

// ErrInvalidHash is returned when the stored hash string cannot be parsed.
var ErrInvalidHash = errors.New("password: invalid hash format")

// Hasher hashes plaintext passwords and verifies them against stored hashes.
type Hasher interface {
	// Hash derives an Argon2id hash from the plaintext password.
	// The returned string is a self-contained PHC-format hash that can be
	// stored directly in the database.
	Hash(password string) (string, error)

	// Verify returns true when password matches the stored hash.
	// It returns (false, nil) for a valid but non-matching hash, and
	// (false, ErrInvalidHash) when the stored hash is malformed.
	Verify(password, hash string) (bool, error)
}

// argon2idHasher is the production implementation of Hasher.
type argon2idHasher struct {
	// pepper is an optional HMAC key applied before hashing. Empty = disabled.
	pepper []byte
}

// New returns a Hasher using Argon2id with the project-standard parameters.
// Pass a non-empty pepper to enable HMAC-pepper pre-processing (recommended
// for production; see CLAUDE.md security profile).
func New(pepper []byte) Hasher {
	return &argon2idHasher{pepper: pepper}
}

// Hash derives a new Argon2id hash for the given password.
func (h *argon2idHasher) Hash(password string) (string, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("password hash: generate salt: %w", err)
	}

	input := h.applyPepper(password)
	key := argon2.IDKey(input, salt, argonTime, argonMemory, argonThreads, keyLen)

	// PHC string format: $argon2id$v=19$m=<mem>,t=<time>,p=<threads>$<salt>$<hash>
	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		argonMemory,
		argonTime,
		argonThreads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	)
	return encoded, nil
}

// Verify checks whether password matches the stored Argon2id hash.
func (h *argon2idHasher) Verify(password, hash string) (bool, error) {
	salt, storedKey, err := parseHash(hash)
	if err != nil {
		return false, err
	}

	input := h.applyPepper(password)
	candidate := argon2.IDKey(input, salt, argonTime, argonMemory, argonThreads, keyLen)

	return subtle.ConstantTimeCompare(candidate, storedKey) == 1, nil
}

// applyPepper returns HMAC-SHA256(pepper, password) when a pepper is set,
// or the raw password bytes when it is not.
func (h *argon2idHasher) applyPepper(password string) []byte {
	if len(h.pepper) == 0 {
		return []byte(password)
	}
	mac := hmac.New(sha256.New, h.pepper)
	mac.Write([]byte(password))
	return mac.Sum(nil)
}

// parseHash splits a PHC-format Argon2id string into its salt and key components.
func parseHash(encoded string) (salt, key []byte, err error) {
	// Expected: $argon2id$v=19$m=19456,t=2,p=1$<salt_b64>$<hash_b64>
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode salt: %s", ErrInvalidHash, err)
	}

	key, err = base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return nil, nil, fmt.Errorf("%w: decode key: %s", ErrInvalidHash, err)
	}

	return salt, key, nil
}
