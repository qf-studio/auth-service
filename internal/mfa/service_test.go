package mfa

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// ── Mock Repository ─────────────────────────────────────────────────────────

type mockRepo struct {
	getMFAStatusFn    func(ctx context.Context, userID string) (*MFAStatus, error)
	saveSecretFn      func(ctx context.Context, userID, secret, algorithm string, digits, period int) error
	getSecretFn       func(ctx context.Context, userID string) (string, bool, error)
	confirmSecretFn   func(ctx context.Context, userID string) error
	deleteSecretFn    func(ctx context.Context, userID string) error
	saveBackupCodesFn func(ctx context.Context, userID string, hashes []string) error
	getBackupCodesFn  func(ctx context.Context, userID string) ([]BackupCodeRecord, error)
	consumeBackupFn   func(ctx context.Context, userID, hash string) error
}

func (m *mockRepo) GetMFAStatus(ctx context.Context, userID string) (*MFAStatus, error) {
	if m.getMFAStatusFn != nil {
		return m.getMFAStatusFn(ctx, userID)
	}
	return nil, ErrMFANotEnabled
}

func (m *mockRepo) SaveSecret(ctx context.Context, userID, secret, algorithm string, digits, period int) error {
	if m.saveSecretFn != nil {
		return m.saveSecretFn(ctx, userID, secret, algorithm, digits, period)
	}
	return nil
}

func (m *mockRepo) GetSecret(ctx context.Context, userID string) (string, bool, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, userID)
	}
	return "", false, ErrMFANotEnabled
}

func (m *mockRepo) ConfirmSecret(ctx context.Context, userID string) error {
	if m.confirmSecretFn != nil {
		return m.confirmSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockRepo) DeleteSecret(ctx context.Context, userID string) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockRepo) SaveBackupCodes(ctx context.Context, userID string, hashes []string) error {
	if m.saveBackupCodesFn != nil {
		return m.saveBackupCodesFn(ctx, userID, hashes)
	}
	return nil
}

func (m *mockRepo) GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error) {
	if m.getBackupCodesFn != nil {
		return m.getBackupCodesFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockRepo) ConsumeBackupCode(ctx context.Context, userID, hash string) error {
	if m.consumeBackupFn != nil {
		return m.consumeBackupFn(ctx, userID, hash)
	}
	return nil
}

// ── Test Helpers ─────────────────────────────────────────────────────────────

func newTestService(t *testing.T, repo *mockRepo) *Service {
	t.Helper()
	logger, _ := zap.NewDevelopment()
	return NewService(repo, logger, "TestIssuer")
}

// generateValidCode produces a valid TOTP code for the given base32 secret.
func generateValidCode(t *testing.T, b32Secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(b32Secret, time.Now().UTC())
	require.NoError(t, err)
	return code
}

// ── EnrollTOTP Tests ────────────────────────────────────────────────────────

func TestEnrollTOTP(t *testing.T) {
	tests := []struct {
		name    string
		repo    *mockRepo
		wantErr error
	}{
		{
			name: "success - no prior MFA",
			repo: &mockRepo{},
		},
		{
			name: "success - replaces unconfirmed enrollment",
			repo: &mockRepo{
				getMFAStatusFn: func(_ context.Context, _ string) (*MFAStatus, error) {
					return &MFAStatus{Enabled: true, Confirmed: false, Method: "totp"}, nil
				},
			},
		},
		{
			name: "error - MFA already confirmed",
			repo: &mockRepo{
				getMFAStatusFn: func(_ context.Context, _ string) (*MFAStatus, error) {
					return &MFAStatus{Enabled: true, Confirmed: true, Method: "totp"}, nil
				},
			},
			wantErr: ErrMFAAlreadyActive,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(t, tt.repo)
			result, err := svc.EnrollTOTP(context.Background(), "user-1", "alice@example.com")

			if tt.wantErr != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, result)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.NotEmpty(t, result.Secret)
			assert.Contains(t, result.OTPAuthURL, "otpauth://totp/")
			assert.Contains(t, result.OTPAuthURL, "TestIssuer")
		})
	}
}

func TestEnrollTOTP_SaveSecretError(t *testing.T) {
	repo := &mockRepo{
		saveSecretFn: func(_ context.Context, _, _, _ string, _, _ int) error {
			return errors.New("db error")
		},
	}
	svc := newTestService(t, repo)
	_, err := svc.EnrollTOTP(context.Background(), "user-1", "alice@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save secret")
}

// ── ConfirmEnrollment Tests ─────────────────────────────────────────────────

func TestConfirmEnrollment_RoundTrip(t *testing.T) {
	// Enroll, then confirm with a valid code.
	var storedSecret string
	var confirmed bool
	var storedHashes []string

	repo := &mockRepo{
		saveSecretFn: func(_ context.Context, _, secret, _ string, _, _ int) error {
			storedSecret = secret
			return nil
		},
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return storedSecret, confirmed, nil
		},
		confirmSecretFn: func(_ context.Context, _ string) error {
			confirmed = true
			return nil
		},
		saveBackupCodesFn: func(_ context.Context, _ string, hashes []string) error {
			storedHashes = hashes
			return nil
		},
	}

	svc := newTestService(t, repo)
	ctx := context.Background()

	// Step 1: Enroll.
	result, err := svc.EnrollTOTP(ctx, "user-1", "alice@example.com")
	require.NoError(t, err)

	// Step 2: Generate valid code from the secret.
	code := generateValidCode(t, result.Secret)

	// Step 3: Confirm.
	backupCodes, err := svc.ConfirmEnrollment(ctx, "user-1", code)
	require.NoError(t, err)
	assert.Len(t, backupCodes, backupCodeCount)
	assert.Len(t, storedHashes, backupCodeCount)

	// Verify each backup code is 8 chars alphanumeric.
	for _, bc := range backupCodes {
		assert.Len(t, bc, backupCodeLen)
		assert.Regexp(t, `^[a-z0-9]+$`, bc)
	}
}

func TestConfirmEnrollment_InvalidCode(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			// Return a known secret for testing.
			return "JBSWY3DPEHPK3PXP", false, nil
		},
	}
	svc := newTestService(t, repo)

	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTOTP)
}

func TestConfirmEnrollment_NoPendingEnrollment(t *testing.T) {
	repo := &mockRepo{} // GetSecret returns ErrMFANotEnabled by default
	svc := newTestService(t, repo)

	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrEnrollmentNotFound)
}

func TestConfirmEnrollment_AlreadyConfirmed(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", true, nil
		},
	}
	svc := newTestService(t, repo)

	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFAAlreadyActive)
}

// ── VerifyTOTP Tests ────────────────────────────────────────────────────────

func TestVerifyTOTP(t *testing.T) {
	// Generate a real secret for round-trip testing.
	var enrolledSecret string

	repo := &mockRepo{
		saveSecretFn: func(_ context.Context, _, secret, _ string, _, _ int) error {
			enrolledSecret = secret
			return nil
		},
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return enrolledSecret, true, nil
		},
	}

	svc := newTestService(t, repo)
	ctx := context.Background()

	// Enroll to get a real secret.
	result, err := svc.EnrollTOTP(ctx, "user-1", "alice@example.com")
	require.NoError(t, err)

	// Generate valid code.
	code := generateValidCode(t, result.Secret)

	// Verify should succeed.
	err = svc.VerifyTOTP(ctx, "user-1", code)
	require.NoError(t, err)
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", true, nil
		},
	}
	svc := newTestService(t, repo)

	err := svc.VerifyTOTP(context.Background(), "user-1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidTOTP)
}

func TestVerifyTOTP_NotConfirmed(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", false, nil
		},
	}
	svc := newTestService(t, repo)

	err := svc.VerifyTOTP(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotConfirmed)
}

func TestVerifyTOTP_NoMFA(t *testing.T) {
	repo := &mockRepo{} // Returns ErrMFANotEnabled
	svc := newTestService(t, repo)

	err := svc.VerifyTOTP(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

// ── VerifyBackupCode Tests ──────────────────────────────────────────────────

func TestVerifyBackupCode_Success(t *testing.T) {
	var consumedHash string
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", true, nil
		},
		consumeBackupFn: func(_ context.Context, _ string, hash string) error {
			consumedHash = hash
			return nil
		},
	}

	svc := newTestService(t, repo)
	err := svc.VerifyBackupCode(context.Background(), "user-1", "abc12345")
	require.NoError(t, err)

	// Verify the hash was computed correctly.
	expectedHash := hashBackupCode("abc12345")
	assert.Equal(t, expectedHash, consumedHash)
}

func TestVerifyBackupCode_Invalid(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", true, nil
		},
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			return ErrBackupCodeInvalid
		},
	}

	svc := newTestService(t, repo)
	err := svc.VerifyBackupCode(context.Background(), "user-1", "wrongcode")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupCodeInvalid)
}

func TestVerifyBackupCode_SingleUse(t *testing.T) {
	// Simulate a code that has already been consumed.
	used := false
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", true, nil
		},
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			if used {
				return ErrBackupCodeInvalid
			}
			used = true
			return nil
		},
	}

	svc := newTestService(t, repo)
	ctx := context.Background()

	// First use succeeds.
	err := svc.VerifyBackupCode(ctx, "user-1", "abc12345")
	require.NoError(t, err)

	// Second use fails (single-use enforcement).
	err = svc.VerifyBackupCode(ctx, "user-1", "abc12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBackupCodeInvalid)
}

func TestVerifyBackupCode_MFANotEnabled(t *testing.T) {
	repo := &mockRepo{} // GetSecret returns ErrMFANotEnabled
	svc := newTestService(t, repo)

	err := svc.VerifyBackupCode(context.Background(), "user-1", "abc12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

func TestVerifyBackupCode_NotConfirmed(t *testing.T) {
	repo := &mockRepo{
		getSecretFn: func(_ context.Context, _ string) (string, bool, error) {
			return "JBSWY3DPEHPK3PXP", false, nil
		},
	}
	svc := newTestService(t, repo)

	err := svc.VerifyBackupCode(context.Background(), "user-1", "abc12345")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

// ── DisableMFA Tests ────────────────────────────────────────────────────────

func TestDisableMFA_Success(t *testing.T) {
	var deleted bool
	repo := &mockRepo{
		getMFAStatusFn: func(_ context.Context, _ string) (*MFAStatus, error) {
			return &MFAStatus{Enabled: true, Confirmed: true, Method: "totp"}, nil
		},
		deleteSecretFn: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}

	svc := newTestService(t, repo)
	err := svc.DisableMFA(context.Background(), "user-1")
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDisableMFA_NotEnabled(t *testing.T) {
	repo := &mockRepo{} // Returns ErrMFANotEnabled
	svc := newTestService(t, repo)

	err := svc.DisableMFA(context.Background(), "user-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

func TestDisableMFA_StatusNotEnabled(t *testing.T) {
	repo := &mockRepo{
		getMFAStatusFn: func(_ context.Context, _ string) (*MFAStatus, error) {
			return &MFAStatus{Enabled: false}, nil
		},
	}
	svc := newTestService(t, repo)

	err := svc.DisableMFA(context.Background(), "user-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMFANotEnabled)
}

// ── TOTP Generation Tests ───────────────────────────────────────────────────

func TestGenerateTOTPSecret(t *testing.T) {
	secret, url, err := generateTOTPSecret("TestIssuer", "alice@example.com")
	require.NoError(t, err)

	assert.NotEmpty(t, secret)
	assert.Contains(t, url, "otpauth://totp/")
	assert.Contains(t, url, "TestIssuer")
	assert.Contains(t, url, "secret=")
}

func TestGenerateTOTPSecret_Uniqueness(t *testing.T) {
	secrets := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		secret, _, err := generateTOTPSecret("TestIssuer", "test@example.com")
		require.NoError(t, err)
		assert.False(t, secrets[secret], "secret collision at iteration %d", i)
		secrets[secret] = true
	}
}

func TestValidateTOTPCode_ValidCode(t *testing.T) {
	secret, _, err := generateTOTPSecret("TestIssuer", "test@example.com")
	require.NoError(t, err)

	code, err := totp.GenerateCode(secret, time.Now().UTC())
	require.NoError(t, err)

	assert.True(t, validateTOTPCode(secret, code))
}

func TestValidateTOTPCode_InvalidCode(t *testing.T) {
	assert.False(t, validateTOTPCode("JBSWY3DPEHPK3PXP", "000000"))
}

func TestValidateTOTPCode_WindowSkew(t *testing.T) {
	secret, _, err := generateTOTPSecret("TestIssuer", "test@example.com")
	require.NoError(t, err)

	// Generate code for 30 seconds ago (within ±1 window).
	pastCode, err := totp.GenerateCode(secret, time.Now().UTC().Add(-totpPeriod*time.Second))
	require.NoError(t, err)

	// Should still be valid within the skew window.
	valid, _ := totp.ValidateCustom(pastCode, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    totpPeriod,
		Skew:     totpSkew,
		Digits:   otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	assert.True(t, valid, "code from -1 period should be accepted within skew window")
}

// ── Backup Code Tests ───────────────────────────────────────────────────────

func TestGenerateBackupCodes(t *testing.T) {
	plaintexts, hashes := generateBackupCodes(backupCodeCount)

	assert.Len(t, plaintexts, backupCodeCount)
	assert.Len(t, hashes, backupCodeCount)

	for i, pt := range plaintexts {
		assert.Len(t, pt, backupCodeLen)
		assert.Regexp(t, `^[a-z0-9]+$`, pt)
		// Verify hash matches.
		assert.Equal(t, hashBackupCode(pt), hashes[i])
	}
}

func TestGenerateBackupCodes_Uniqueness(t *testing.T) {
	plaintexts, _ := generateBackupCodes(backupCodeCount)
	seen := make(map[string]bool, backupCodeCount)
	for _, code := range plaintexts {
		assert.False(t, seen[code], "duplicate backup code: %s", code)
		seen[code] = true
	}
}

func TestHashBackupCode_Deterministic(t *testing.T) {
	code := "abc12345"
	h1 := hashBackupCode(code)
	h2 := hashBackupCode(code)
	assert.Equal(t, h1, h2)
	assert.Len(t, h1, 64) // SHA-256 hex = 64 chars
}

func TestHashBackupCode_DifferentInputs(t *testing.T) {
	h1 := hashBackupCode("code0001")
	h2 := hashBackupCode("code0002")
	assert.NotEqual(t, h1, h2)
}
