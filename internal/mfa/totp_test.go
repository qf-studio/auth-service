package mfa

import (
	"encoding/base32"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestGenerateSecret(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Decode and verify length is 160 bits (20 bytes).
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	require.NoError(t, err)
	assert.Equal(t, domain.TOTPSecretLen, len(decoded))
}

func TestGenerateSecret_Uniqueness(t *testing.T) {
	secrets := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		s, err := GenerateSecret()
		require.NoError(t, err)
		secrets[s] = struct{}{}
	}
	assert.Equal(t, 100, len(secrets), "all generated secrets should be unique")
}

func TestGenerateProvisioningURI(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)

	uri, err := GenerateProvisioningURI(secret, "QuantFlow", "user@example.com")
	require.NoError(t, err)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "secret="+secret)
	assert.Contains(t, uri, "issuer=QuantFlow")
	assert.Contains(t, uri, "user@example.com")
}

func TestValidateCode_RoundTrip(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCodeAt(secret, now)
	require.NoError(t, err)

	assert.True(t, ValidateCodeAt(secret, code, now), "code should be valid at generation time")
}

func TestValidateCode_SkewWindow(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCodeAt(secret, now)
	require.NoError(t, err)

	tests := []struct {
		name    string
		offset  time.Duration
		valid   bool
	}{
		{"current period", 0, true},
		{"one period back", -time.Duration(domain.TOTPPeriod) * time.Second, true},
		{"one period ahead", time.Duration(domain.TOTPPeriod) * time.Second, true},
		{"two periods back", -2 * time.Duration(domain.TOTPPeriod) * time.Second, false},
		{"two periods ahead", 2 * time.Duration(domain.TOTPPeriod) * time.Second, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateCodeAt(secret, code, now.Add(tt.offset))
			assert.Equal(t, tt.valid, result)
		})
	}
}

func TestValidateCode_InvalidInputs(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)

	tests := []struct {
		name   string
		secret string
		code   string
	}{
		{"empty code", secret, ""},
		{"wrong code", secret, "000000"},
		{"non-numeric code", secret, "abcdef"},
		{"too short", secret, "12345"},
		{"too long", secret, "1234567"},
		{"empty secret", "", "123456"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, ValidateCode(tt.secret, tt.code))
		})
	}
}

func TestValidateCode_DifferentSecrets(t *testing.T) {
	secret1, err := GenerateSecret()
	require.NoError(t, err)
	secret2, err := GenerateSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateCodeAt(secret1, now)
	require.NoError(t, err)

	assert.True(t, ValidateCodeAt(secret1, code, now))
	assert.False(t, ValidateCodeAt(secret2, code, now), "code from secret1 should not work with secret2")
}
