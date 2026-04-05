package mfa

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/qf-studio/auth-service/internal/domain"
)

// alphanumeric character set for backup codes (no ambiguous chars like 0/O, 1/l).
const backupCodeAlphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

// GenerateBackupCodes creates a set of random alphanumeric backup codes.
func GenerateBackupCodes() ([]string, error) {
	return GenerateBackupCodesN(domain.BackupCodeCount, domain.BackupCodeLength)
}

// GenerateBackupCodesN creates n random alphanumeric backup codes of the given length.
func GenerateBackupCodesN(count, length int) ([]string, error) {
	codes := make([]string, 0, count)
	alphabetLen := big.NewInt(int64(len(backupCodeAlphabet)))

	for i := 0; i < count; i++ {
		code := make([]byte, length)
		for j := 0; j < length; j++ {
			idx, err := rand.Int(rand.Reader, alphabetLen)
			if err != nil {
				return nil, fmt.Errorf("generate backup code: %w", err)
			}
			code[j] = backupCodeAlphabet[idx.Int64()]
		}
		codes = append(codes, string(code))
	}

	return codes, nil
}

// HashBackupCode returns the SHA-256 hex digest of a backup code.
func HashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// VerifyBackupCode performs a constant-time comparison of a plaintext code
// against a SHA-256 hash to prevent timing attacks.
func VerifyBackupCode(code, hash string) bool {
	codeHash := HashBackupCode(code)
	return subtle.ConstantTimeCompare([]byte(codeHash), []byte(hash)) == 1
}
