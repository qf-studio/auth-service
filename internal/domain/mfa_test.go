package domain

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestMFASecret_Fields(t *testing.T) {
	now := time.Now()
	secret := MFASecret{
		ID:              "mfa-123",
		UserID:          "user-456",
		EncryptedSecret: "encrypted-data",
		Algorithm:       "SHA1",
		Digits:          6,
		Period:          30,
		Confirmed:       false,
		CreatedAt:       now,
	}

	assert.Equal(t, "mfa-123", secret.ID)
	assert.Equal(t, "user-456", secret.UserID)
	assert.Equal(t, "encrypted-data", secret.EncryptedSecret)
	assert.Equal(t, "SHA1", secret.Algorithm)
	assert.Equal(t, 6, secret.Digits)
	assert.Equal(t, 30, secret.Period)
	assert.False(t, secret.Confirmed)
	assert.Equal(t, now, secret.CreatedAt)
}

func TestBackupCode_Fields(t *testing.T) {
	now := time.Now()
	usedAt := now.Add(time.Hour)
	code := BackupCode{
		ID:        "bc-123",
		UserID:    "user-456",
		CodeHash:  "hashed-code",
		Used:      true,
		UsedAt:    &usedAt,
		CreatedAt: now,
	}

	assert.Equal(t, "bc-123", code.ID)
	assert.Equal(t, "user-456", code.UserID)
	assert.Equal(t, "hashed-code", code.CodeHash)
	assert.True(t, code.Used)
	assert.NotNil(t, code.UsedAt)
	assert.Equal(t, usedAt, *code.UsedAt)
	assert.Equal(t, now, code.CreatedAt)
}

func TestBackupCode_UnusedHasNilUsedAt(t *testing.T) {
	code := BackupCode{
		ID:       "bc-789",
		UserID:   "user-456",
		CodeHash: "hashed-code",
		Used:     false,
		UsedAt:   nil,
	}

	assert.False(t, code.Used)
	assert.Nil(t, code.UsedAt)
}

func TestMFAStatusResponse_Serialization(t *testing.T) {
	status := MFAStatusResponse{
		Enabled:         true,
		Confirmed:       true,
		BackupCodesLeft: 8,
	}

	assert.True(t, status.Enabled)
	assert.True(t, status.Confirmed)
	assert.Equal(t, 8, status.BackupCodesLeft)
}

func TestMFASetupResponse_Fields(t *testing.T) {
	resp := MFASetupResponse{
		Secret:      "JBSWY3DPEHPK3PXP",
		QRCodeURI:   "otpauth://totp/QuantFlow:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=QuantFlow",
		BackupCodes: []string{"code1", "code2", "code3"},
	}

	assert.Equal(t, "JBSWY3DPEHPK3PXP", resp.Secret)
	assert.Contains(t, resp.QRCodeURI, "otpauth://totp/")
	assert.Len(t, resp.BackupCodes, 3)
}
