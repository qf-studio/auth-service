package mfa

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func newTestService() *Service {
	return NewService("TestIssuer")
}

func TestNewService(t *testing.T) {
	svc := NewService("MyIssuer")
	assert.NotNil(t, svc)
	assert.Equal(t, "MyIssuer", svc.issuer)
}

func TestStartEnrollment(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.Secret)
	assert.Contains(t, result.ProvisioningURI, "otpauth://totp/")
	assert.Contains(t, result.ProvisioningURI, "user@example.com")
	assert.Contains(t, result.ProvisioningURI, "TestIssuer")
	assert.Len(t, result.BackupCodes, domain.BackupCodeCount)
}

func TestStartEnrollment_UniqueSecrets(t *testing.T) {
	svc := newTestService()
	secrets := make(map[string]struct{})

	for i := 0; i < 10; i++ {
		result, err := svc.StartEnrollment("user@example.com")
		require.NoError(t, err)
		_, exists := secrets[result.Secret]
		assert.False(t, exists, "secrets should be unique across enrollments")
		secrets[result.Secret] = struct{}{}
	}
}

func TestConfirmEnrollment_ValidCode(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	code, err := GenerateCodeAt(result.Secret, time.Now())
	require.NoError(t, err)

	err = svc.ConfirmEnrollment(result.Secret, code)
	assert.NoError(t, err)
}

func TestConfirmEnrollment_InvalidCode(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	err = svc.ConfirmEnrollment(result.Secret, "000000")
	assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)
}

func TestVerifyTOTP_Success(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	code, err := GenerateCodeAt(result.Secret, time.Now())
	require.NoError(t, err)

	err = svc.VerifyTOTP(result.Secret, true, code)
	assert.NoError(t, err)
}

func TestVerifyTOTP_NotConfirmed(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	code, err := GenerateCodeAt(result.Secret, time.Now())
	require.NoError(t, err)

	err = svc.VerifyTOTP(result.Secret, false, code)
	assert.ErrorIs(t, err, domain.ErrMFANotConfirmed)
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	err = svc.VerifyTOTP(result.Secret, true, "999999")
	assert.ErrorIs(t, err, domain.ErrInvalidTOTPCode)
}

func TestVerifyBackupCode_Success(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	backupCodes := svc.HashBackupCodes("user-1", result.BackupCodes)

	// First code should match.
	idx, err := svc.VerifyBackupCode(result.BackupCodes[0], backupCodes)
	assert.NoError(t, err)
	assert.Equal(t, 0, idx)

	// Last code should also match.
	idx, err = svc.VerifyBackupCode(result.BackupCodes[len(result.BackupCodes)-1], backupCodes)
	assert.NoError(t, err)
	assert.Equal(t, len(result.BackupCodes)-1, idx)
}

func TestVerifyBackupCode_InvalidCode(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	backupCodes := svc.HashBackupCodes("user-1", result.BackupCodes)

	_, err = svc.VerifyBackupCode("INVALIDCODE", backupCodes)
	assert.ErrorIs(t, err, domain.ErrInvalidBackupCode)
}

func TestVerifyBackupCode_UsedCode(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	backupCodes := svc.HashBackupCodes("user-1", result.BackupCodes)

	// Mark first code as used.
	now := time.Now()
	backupCodes[0].Used = true
	backupCodes[0].UsedAt = &now

	// Used code should not match.
	_, err = svc.VerifyBackupCode(result.BackupCodes[0], backupCodes)
	assert.ErrorIs(t, err, domain.ErrInvalidBackupCode)
}

func TestVerifyBackupCode_SingleUse(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	backupCodes := svc.HashBackupCodes("user-1", result.BackupCodes)
	code := result.BackupCodes[3]

	// First use succeeds.
	idx, err := svc.VerifyBackupCode(code, backupCodes)
	require.NoError(t, err)
	assert.Equal(t, 3, idx)

	// Simulate marking as used.
	now := time.Now()
	backupCodes[idx].Used = true
	backupCodes[idx].UsedAt = &now

	// Second use fails.
	_, err = svc.VerifyBackupCode(code, backupCodes)
	assert.ErrorIs(t, err, domain.ErrInvalidBackupCode)
}

func TestVerifyBackupCode_EmptyList(t *testing.T) {
	svc := newTestService()
	_, err := svc.VerifyBackupCode("ANYCODE", nil)
	assert.ErrorIs(t, err, domain.ErrNoBackupCodes)

	_, err = svc.VerifyBackupCode("ANYCODE", []domain.BackupCode{})
	assert.ErrorIs(t, err, domain.ErrNoBackupCodes)
}

func TestVerifyBackupCode_AllUsed(t *testing.T) {
	svc := newTestService()

	result, err := svc.StartEnrollment("user@example.com")
	require.NoError(t, err)

	backupCodes := svc.HashBackupCodes("user-1", result.BackupCodes)

	// Mark all as used.
	now := time.Now()
	for i := range backupCodes {
		backupCodes[i].Used = true
		backupCodes[i].UsedAt = &now
	}

	_, err = svc.VerifyBackupCode(result.BackupCodes[0], backupCodes)
	assert.ErrorIs(t, err, domain.ErrInvalidBackupCode)
}

func TestHashBackupCodes(t *testing.T) {
	svc := newTestService()

	codes := []string{"CODE1", "CODE2", "CODE3"}
	hashed := svc.HashBackupCodes("user-1", codes)

	assert.Len(t, hashed, 3)
	for i, bc := range hashed {
		assert.Equal(t, "user-1", bc.UserID)
		assert.Equal(t, HashBackupCode(codes[i]), bc.CodeHash)
		assert.False(t, bc.Used)
		assert.Nil(t, bc.UsedAt)
		assert.False(t, bc.CreatedAt.IsZero())
	}
}

func TestEnrollmentRoundTrip(t *testing.T) {
	svc := newTestService()

	// Step 1: Start enrollment.
	enrollment, err := svc.StartEnrollment("alice@example.com")
	require.NoError(t, err)

	// Step 2: Confirm with valid TOTP code.
	code, err := GenerateCodeAt(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = svc.ConfirmEnrollment(enrollment.Secret, code)
	require.NoError(t, err)

	// Step 3: Verify TOTP works post-confirmation.
	code2, err := GenerateCodeAt(enrollment.Secret, time.Now())
	require.NoError(t, err)
	err = svc.VerifyTOTP(enrollment.Secret, true, code2)
	assert.NoError(t, err)

	// Step 4: Backup codes work.
	backupCodes := svc.HashBackupCodes("alice-id", enrollment.BackupCodes)
	idx, err := svc.VerifyBackupCode(enrollment.BackupCodes[5], backupCodes)
	assert.NoError(t, err)
	assert.Equal(t, 5, idx)
}
