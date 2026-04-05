package mfa

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestGenerateBackupCodes(t *testing.T) {
	codes, err := GenerateBackupCodes()
	require.NoError(t, err)
	assert.Len(t, codes, domain.BackupCodeCount)

	for _, code := range codes {
		assert.Len(t, code, domain.BackupCodeLength)
		// All chars should be from the alphabet.
		for _, c := range code {
			assert.Contains(t, backupCodeAlphabet, string(c))
		}
	}
}

func TestGenerateBackupCodes_Uniqueness(t *testing.T) {
	codes, err := GenerateBackupCodes()
	require.NoError(t, err)

	seen := make(map[string]struct{})
	for _, code := range codes {
		_, exists := seen[code]
		assert.False(t, exists, "duplicate code: %s", code)
		seen[code] = struct{}{}
	}
}

func TestGenerateBackupCodesN(t *testing.T) {
	tests := []struct {
		name   string
		count  int
		length int
	}{
		{"default", 10, 8},
		{"fewer codes", 5, 8},
		{"longer codes", 10, 12},
		{"single code", 1, 8},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			codes, err := GenerateBackupCodesN(tt.count, tt.length)
			require.NoError(t, err)
			assert.Len(t, codes, tt.count)
			for _, code := range codes {
				assert.Len(t, code, tt.length)
			}
		})
	}
}

func TestHashBackupCode(t *testing.T) {
	code := "ABCD1234"
	hash := HashBackupCode(code)

	assert.Len(t, hash, 64, "SHA-256 hex digest should be 64 chars")
	// Same input should produce same hash.
	assert.Equal(t, hash, HashBackupCode(code))
	// Different input should produce different hash.
	assert.NotEqual(t, hash, HashBackupCode("DIFFERENT"))
}

func TestVerifyBackupCode(t *testing.T) {
	code := "TESTCODE"
	hash := HashBackupCode(code)

	tests := []struct {
		name  string
		code  string
		hash  string
		valid bool
	}{
		{"correct code", code, hash, true},
		{"wrong code", "WRONGCODE", hash, false},
		{"empty code", "", hash, false},
		{"case sensitive", "testcode", hash, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, VerifyBackupCode(tt.code, tt.hash))
		})
	}
}

func TestVerifyBackupCode_ConstantTime(t *testing.T) {
	// Verify that correct and incorrect codes both complete (no timing leaks
	// visible at the API level — this is a smoke test, not a statistical timing test).
	hash := HashBackupCode("REALCODE")
	assert.True(t, VerifyBackupCode("REALCODE", hash))
	assert.False(t, VerifyBackupCode("FAKECODE", hash))
}
