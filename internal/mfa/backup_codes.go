package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"math/big"
)

const (
	// backupCodeCount is the number of backup codes generated per enrollment.
	backupCodeCount = 10

	// backupCodeLen is the length of each plaintext backup code.
	backupCodeLen = 8
)

// backupCodeAlphabet is alphanumeric (0-9, a-z) for human readability.
var backupCodeAlphabet = []byte("abcdefghijklmnopqrstuvwxyz0123456789")

// generateBackupCodes produces backupCodeCount random codes and their SHA-256 hashes.
// Returns (plaintext codes, hashed codes).
func generateBackupCodes(count int) ([]string, []string) {
	plaintexts := make([]string, count)
	hashes := make([]string, count)

	for i := 0; i < count; i++ {
		code := generateRandomCode(backupCodeLen)
		plaintexts[i] = code
		hashes[i] = hashBackupCode(code)
	}

	return plaintexts, hashes
}

// generateRandomCode produces a cryptographically random alphanumeric string.
func generateRandomCode(length int) string {
	result := make([]byte, length)
	max := big.NewInt(int64(len(backupCodeAlphabet)))

	for i := 0; i < length; i++ {
		idx, err := rand.Int(rand.Reader, max)
		if err != nil {
			// crypto/rand failure is fatal — should never happen.
			panic("crypto/rand failed: " + err.Error())
		}
		result[i] = backupCodeAlphabet[idx.Int64()]
	}

	return string(result)
}

// hashBackupCode returns the hex-encoded SHA-256 hash of a backup code.
func hashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}
