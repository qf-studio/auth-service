package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMFAStatus_Values(t *testing.T) {
	assert.Equal(t, MFAStatus("disabled"), MFAStatusDisabled)
	assert.Equal(t, MFAStatus("pending"), MFAStatusPending)
	assert.Equal(t, MFAStatus("enabled"), MFAStatusEnabled)
}

func TestMFASecret_Fields(t *testing.T) {
	now := time.Now()
	secret := MFASecret{
		ID:              "mfa-123",
		UserID:          "user-456",
		EncryptedSecret: "enc-secret-data",
		Algorithm:       TOTPAlgorithmSHA1,
		Digits:          TOTPDefaultDigits,
		Period:          TOTPDefaultPeriod,
		Confirmed:       false,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	assert.Equal(t, "mfa-123", secret.ID)
	assert.Equal(t, "user-456", secret.UserID)
	assert.Equal(t, "enc-secret-data", secret.EncryptedSecret)
	assert.Equal(t, "SHA1", secret.Algorithm)
	assert.Equal(t, 6, secret.Digits)
	assert.Equal(t, 30, secret.Period)
	assert.False(t, secret.Confirmed)
}

func TestBackupCode_Fields(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(time.Hour)
	code := BackupCode{
		ID:        "bc-789",
		UserID:    "user-456",
		CodeHash:  "sha256-hash",
		Used:      true,
		UsedAt:    &usedAt,
		CreatedAt: now,
	}

	assert.Equal(t, "bc-789", code.ID)
	assert.Equal(t, "user-456", code.UserID)
	assert.Equal(t, "sha256-hash", code.CodeHash)
	assert.True(t, code.Used)
	assert.NotNil(t, code.UsedAt)
}

func TestBackupCode_UnusedHasNilUsedAt(t *testing.T) {
	code := BackupCode{
		ID:       "bc-001",
		UserID:   "user-001",
		CodeHash: "hash",
		Used:     false,
	}

	assert.False(t, code.Used)
	assert.Nil(t, code.UsedAt)
}

func TestTOTPConstants(t *testing.T) {
	assert.Equal(t, "SHA1", TOTPAlgorithmSHA1)
	assert.Equal(t, 6, TOTPDefaultDigits)
	assert.Equal(t, 30, TOTPDefaultPeriod)
	assert.Equal(t, 10, BackupCodeCount)
	assert.Equal(t, 8, BackupCodeLength)
}

func TestNewValidator_TOTPVerifyRequest(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		req     TOTPVerifyRequest
		wantErr bool
	}{
		{
			name:    "valid 6-digit code",
			req:     TOTPVerifyRequest{Code: "123456"},
			wantErr: false,
		},
		{
			name:    "empty code",
			req:     TOTPVerifyRequest{Code: ""},
			wantErr: true,
		},
		{
			name:    "too short code",
			req:     TOTPVerifyRequest{Code: "12345"},
			wantErr: true,
		},
		{
			name:    "too long code",
			req:     TOTPVerifyRequest{Code: "1234567"},
			wantErr: true,
		},
		{
			name:    "non-numeric code",
			req:     TOTPVerifyRequest{Code: "abcdef"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestNewValidator_MFAVerifyLoginRequest(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		req     MFAVerifyLoginRequest
		wantErr bool
	}{
		{
			name:    "valid request",
			req:     MFAVerifyLoginRequest{MFAToken: "mfa-token-123", Code: "654321"},
			wantErr: false,
		},
		{
			name:    "missing mfa_token",
			req:     MFAVerifyLoginRequest{Code: "654321"},
			wantErr: true,
		},
		{
			name:    "missing code",
			req:     MFAVerifyLoginRequest{MFAToken: "mfa-token-123"},
			wantErr: true,
		},
		{
			name:    "both missing",
			req:     MFAVerifyLoginRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
