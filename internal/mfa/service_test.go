package mfa

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mocks ---

type mockMFARepo struct {
	secret      *domain.MFASecret
	backupCodes []domain.BackupCode
	confirmed   bool
	deleted     bool

	saveSecretErr      error
	getSecretErr       error
	confirmSecretErr   error
	deleteSecretErr    error
	saveBackupErr      error
	getBackupErr       error
	consumeBackupErr   error
	getMFAStatusErr    error
	consumeBackupHash  string // last hash passed to ConsumeBackupCode
}

func (m *mockMFARepo) SaveSecret(_ context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	if m.saveSecretErr != nil {
		return nil, m.saveSecretErr
	}
	m.secret = secret
	return secret, nil
}

func (m *mockMFARepo) GetSecret(_ context.Context, _ string) (*domain.MFASecret, error) {
	// If a secret has been saved, return it regardless of initial getSecretErr.
	if m.secret != nil {
		return m.secret, nil
	}
	if m.getSecretErr != nil {
		return nil, m.getSecretErr
	}
	return nil, storage.ErrNotFound
}

func (m *mockMFARepo) ConfirmSecret(_ context.Context, _ string) error {
	if m.confirmSecretErr != nil {
		return m.confirmSecretErr
	}
	if m.secret != nil {
		m.secret.Confirmed = true
		now := time.Now().UTC()
		m.secret.ConfirmedAt = &now
	}
	m.confirmed = true
	return nil
}

func (m *mockMFARepo) DeleteSecret(_ context.Context, _ string) error {
	if m.deleteSecretErr != nil {
		return m.deleteSecretErr
	}
	if m.secret == nil {
		return storage.ErrNotFound
	}
	m.deleted = true
	m.secret = nil
	return nil
}

func (m *mockMFARepo) SaveBackupCodes(_ context.Context, _ string, codes []domain.BackupCode) error {
	if m.saveBackupErr != nil {
		return m.saveBackupErr
	}
	m.backupCodes = codes
	return nil
}

func (m *mockMFARepo) GetBackupCodes(_ context.Context, _ string) ([]domain.BackupCode, error) {
	if m.getBackupErr != nil {
		return nil, m.getBackupErr
	}
	return m.backupCodes, nil
}

func (m *mockMFARepo) ConsumeBackupCode(_ context.Context, _ string, codeHash string) error {
	if m.consumeBackupErr != nil {
		return m.consumeBackupErr
	}
	m.consumeBackupHash = codeHash
	for i, c := range m.backupCodes {
		if c.CodeHash == codeHash && !c.Used {
			m.backupCodes[i].Used = true
			now := time.Now().UTC()
			m.backupCodes[i].UsedAt = &now
			return nil
		}
	}
	return storage.ErrNotFound
}

func (m *mockMFARepo) GetMFAStatus(_ context.Context, _ string) (*domain.MFAStatus, error) {
	if m.getMFAStatusErr != nil {
		return nil, m.getMFAStatusErr
	}
	status := &domain.MFAStatus{
		UserID: "test-user",
	}
	if m.secret != nil {
		status.Enabled = m.secret.Confirmed
		status.Type = m.secret.Type
		status.Confirmed = m.secret.Confirmed
	}
	unused := 0
	for _, c := range m.backupCodes {
		if !c.Used {
			unused++
		}
	}
	status.BackupLeft = unused
	return status, nil
}

type mockRateLimiter struct {
	attempts    int
	maxAttempts int
	clearErr    error
	recordErr   error
}

func newMockRateLimiter(max int) *mockRateLimiter {
	return &mockRateLimiter{maxAttempts: max}
}

func (m *mockRateLimiter) RecordFailedAttempt(_ context.Context, _ string) (int, error) {
	if m.recordErr != nil {
		return 0, m.recordErr
	}
	m.attempts++
	if m.attempts >= m.maxAttempts {
		return m.attempts, storage.ErrMFAMaxAttempts
	}
	return m.attempts, nil
}

func (m *mockRateLimiter) ClearFailedAttempts(_ context.Context, _ string) error {
	if m.clearErr != nil {
		return m.clearErr
	}
	m.attempts = 0
	return nil
}

// --- Helpers ---

func newTestService(repo *mockMFARepo, limiter *mockRateLimiter) *Service {
	return NewService(repo, limiter, zap.NewNop(), audit.NopLogger{})
}

func enrollTestUser(t *testing.T, svc *Service, repo *mockMFARepo) *EnrollmentResult {
	t.Helper()
	result, err := svc.EnrollTOTP(context.Background(), "test-user")
	require.NoError(t, err)
	require.NotNil(t, result)
	return result
}

func generateValidCode(t *testing.T, secret string) string {
	t.Helper()
	code, err := totp.GenerateCode(secret, time.Now().UTC())
	require.NoError(t, err)
	return code
}

// --- Tests ---

func TestEnrollTOTP(t *testing.T) {
	t.Run("successful enrollment", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		result, err := svc.EnrollTOTP(context.Background(), "test-user")

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.NotEmpty(t, result.Secret)
		assert.Contains(t, result.QRCodeURI, "otpauth://totp/")
		assert.Contains(t, result.QRCodeURI, "QuantFlow")
		assert.Len(t, result.BackupCodes, backupCodeCount)

		// Verify backup codes are 8-char lowercase alphanumeric.
		for _, code := range result.BackupCodes {
			assert.Len(t, code, backupCodeLength)
			for _, c := range code {
				assert.Contains(t, backupCodeAlphabet, string(c))
			}
		}

		// Verify secret was saved unconfirmed.
		assert.NotNil(t, repo.secret)
		assert.False(t, repo.secret.Confirmed)
		assert.Equal(t, "totp", repo.secret.Type)

		// Verify backup codes were persisted (hashed).
		assert.Len(t, repo.backupCodes, backupCodeCount)
		for i, bc := range repo.backupCodes {
			expectedHash := hashBackupCode(result.BackupCodes[i])
			assert.Equal(t, expectedHash, bc.CodeHash)
			assert.False(t, bc.Used)
		}
	})

	t.Run("already enrolled", func(t *testing.T) {
		repo := &mockMFARepo{
			secret: &domain.MFASecret{
				ID:        "existing",
				UserID:    "test-user",
				Type:      "totp",
				Confirmed: true,
			},
		}
		svc := newTestService(repo, newMockRateLimiter(5))

		result, err := svc.EnrollTOTP(context.Background(), "test-user")

		assert.ErrorIs(t, err, ErrMFAAlreadyEnrolled)
		assert.Nil(t, result)
	})

	t.Run("repo error on check", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: errors.New("db down")}
		svc := newTestService(repo, newMockRateLimiter(5))

		result, err := svc.EnrollTOTP(context.Background(), "test-user")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "check existing mfa")
		assert.Nil(t, result)
	})

	t.Run("save secret error", func(t *testing.T) {
		repo := &mockMFARepo{
			getSecretErr:  storage.ErrNotFound,
			saveSecretErr: errors.New("db write failed"),
		}
		svc := newTestService(repo, newMockRateLimiter(5))

		result, err := svc.EnrollTOTP(context.Background(), "test-user")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "save mfa secret")
		assert.Nil(t, result)
	})

	t.Run("save backup codes error", func(t *testing.T) {
		repo := &mockMFARepo{
			getSecretErr:  storage.ErrNotFound,
			saveBackupErr: errors.New("db write failed"),
		}
		svc := newTestService(repo, newMockRateLimiter(5))

		result, err := svc.EnrollTOTP(context.Background(), "test-user")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "save backup codes")
		assert.Nil(t, result)
	})
}

func TestConfirmEnrollment(t *testing.T) {
	t.Run("successful confirmation", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		result := enrollTestUser(t, svc, repo)

		code := generateValidCode(t, result.Secret)
		err := svc.ConfirmEnrollment(context.Background(), "test-user", code)

		require.NoError(t, err)
		assert.True(t, repo.confirmed)
		assert.True(t, repo.secret.Confirmed)
	})

	t.Run("invalid code", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))
		enrollTestUser(t, svc, repo)

		err := svc.ConfirmEnrollment(context.Background(), "test-user", "000000")

		assert.ErrorIs(t, err, ErrInvalidTOTP)
	})

	t.Run("no enrollment", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.ConfirmEnrollment(context.Background(), "test-user", "123456")

		assert.ErrorIs(t, err, ErrMFANotEnrolled)
	})

	t.Run("already confirmed", func(t *testing.T) {
		repo := &mockMFARepo{
			secret: &domain.MFASecret{
				UserID:    "test-user",
				Secret:    "JBSWY3DPEHPK3PXP",
				Confirmed: true,
			},
		}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.ConfirmEnrollment(context.Background(), "test-user", "123456")

		assert.ErrorIs(t, err, ErrMFAAlreadyEnrolled)
	})

	t.Run("confirm secret repo error", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		result := enrollTestUser(t, svc, repo)
		repo.confirmSecretErr = errors.New("db error")

		code := generateValidCode(t, result.Secret)
		err := svc.ConfirmEnrollment(context.Background(), "test-user", code)

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "confirm mfa secret")
	})
}

func TestVerifyTOTP(t *testing.T) {
	t.Run("successful verification", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)

		// Confirm enrollment first.
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Verify TOTP.
		code2 := generateValidCode(t, result.Secret)
		err := svc.VerifyTOTP(context.Background(), "test-user", code2)

		assert.NoError(t, err)
	})

	t.Run("invalid code increments failed attempts", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		err := svc.VerifyTOTP(context.Background(), "test-user", "000000")

		assert.ErrorIs(t, err, ErrInvalidTOTP)
		assert.Equal(t, 1, limiter.attempts)
	})

	t.Run("max attempts exceeded", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(3)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Exhaust attempts.
		for i := 0; i < 2; i++ {
			err := svc.VerifyTOTP(context.Background(), "test-user", "000000")
			assert.ErrorIs(t, err, ErrInvalidTOTP)
		}

		// Third attempt triggers rate limit.
		err := svc.VerifyTOTP(context.Background(), "test-user", "000000")
		assert.ErrorIs(t, err, ErrMaxAttempts)
	})

	t.Run("not enrolled", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.VerifyTOTP(context.Background(), "test-user", "123456")

		assert.ErrorIs(t, err, ErrMFANotEnrolled)
	})

	t.Run("not confirmed", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))
		enrollTestUser(t, svc, repo)

		err := svc.VerifyTOTP(context.Background(), "test-user", "123456")

		assert.ErrorIs(t, err, ErrMFANotConfirmed)
	})

	t.Run("successful verification clears failed attempts", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Fail once.
		_ = svc.VerifyTOTP(context.Background(), "test-user", "000000")
		assert.Equal(t, 1, limiter.attempts)

		// Succeed — attempts should be cleared.
		code2 := generateValidCode(t, result.Secret)
		err := svc.VerifyTOTP(context.Background(), "test-user", code2)
		assert.NoError(t, err)
		assert.Equal(t, 0, limiter.attempts)
	})
}

func TestVerifyBackupCode(t *testing.T) {
	t.Run("successful verification and consumption", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Use first backup code.
		err := svc.VerifyBackupCode(context.Background(), "test-user", result.BackupCodes[0])

		assert.NoError(t, err)
		// Verify the code was consumed (marked as used).
		assert.True(t, repo.backupCodes[0].Used)
	})

	t.Run("single-use enforcement", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Use backup code once.
		backupCode := result.BackupCodes[0]
		err := svc.VerifyBackupCode(context.Background(), "test-user", backupCode)
		require.NoError(t, err)

		// Try to use same code again — should fail.
		err = svc.VerifyBackupCode(context.Background(), "test-user", backupCode)
		assert.ErrorIs(t, err, ErrInvalidBackupCode)
	})

	t.Run("invalid backup code", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		err := svc.VerifyBackupCode(context.Background(), "test-user", "invalidcode")

		assert.ErrorIs(t, err, ErrInvalidBackupCode)
		assert.Equal(t, 1, limiter.attempts)
	})

	t.Run("max attempts via backup code", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(3)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Exhaust attempts with invalid codes.
		for i := 0; i < 2; i++ {
			_ = svc.VerifyBackupCode(context.Background(), "test-user", "badcode")
		}

		err := svc.VerifyBackupCode(context.Background(), "test-user", "badcode")
		assert.ErrorIs(t, err, ErrMaxAttempts)
	})

	t.Run("not enrolled", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.VerifyBackupCode(context.Background(), "test-user", "somecode")

		assert.ErrorIs(t, err, ErrMFANotEnrolled)
	})

	t.Run("not confirmed", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))
		enrollTestUser(t, svc, repo)

		err := svc.VerifyBackupCode(context.Background(), "test-user", "somecode")

		assert.ErrorIs(t, err, ErrMFANotConfirmed)
	})

	t.Run("case insensitive and trimmed", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Backup codes are lowercase, try with uppercase + spaces.
		backupCode := result.BackupCodes[0]
		err := svc.VerifyBackupCode(context.Background(), "test-user", "  "+strings.ToUpper(backupCode)+"  ")

		assert.NoError(t, err)
	})

	t.Run("successful verification clears failed attempts", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		limiter := newMockRateLimiter(5)
		svc := newTestService(repo, limiter)

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		// Fail once.
		_ = svc.VerifyBackupCode(context.Background(), "test-user", "badcode")
		assert.Equal(t, 1, limiter.attempts)

		// Succeed.
		err := svc.VerifyBackupCode(context.Background(), "test-user", result.BackupCodes[0])
		assert.NoError(t, err)
		assert.Equal(t, 0, limiter.attempts)
	})
}

func TestDisableMFA(t *testing.T) {
	t.Run("successful disable", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))
		enrollTestUser(t, svc, repo)

		err := svc.DisableMFA(context.Background(), "test-user")

		assert.NoError(t, err)
		assert.True(t, repo.deleted)
	})

	t.Run("not enrolled", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.DisableMFA(context.Background(), "test-user")

		assert.ErrorIs(t, err, ErrMFANotEnrolled)
	})

	t.Run("repo error", func(t *testing.T) {
		repo := &mockMFARepo{
			secret:          &domain.MFASecret{UserID: "test-user"},
			deleteSecretErr: errors.New("db error"),
		}
		svc := newTestService(repo, newMockRateLimiter(5))

		err := svc.DisableMFA(context.Background(), "test-user")

		assert.Error(t, err)
		assert.Contains(t, err.Error(), "delete mfa secret")
	})
}

func TestGetStatus(t *testing.T) {
	t.Run("no enrollment", func(t *testing.T) {
		repo := &mockMFARepo{}
		svc := newTestService(repo, newMockRateLimiter(5))

		status, err := svc.GetStatus(context.Background(), "test-user")

		require.NoError(t, err)
		assert.False(t, status.Enabled)
		assert.Empty(t, status.Type)
	})

	t.Run("enrolled and confirmed", func(t *testing.T) {
		repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
		svc := newTestService(repo, newMockRateLimiter(5))

		result := enrollTestUser(t, svc, repo)
		code := generateValidCode(t, result.Secret)
		require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

		status, err := svc.GetStatus(context.Background(), "test-user")

		require.NoError(t, err)
		assert.True(t, status.Enabled)
		assert.Equal(t, "totp", status.Type)
		assert.Equal(t, backupCodeCount, status.BackupLeft)
	})

	t.Run("repo error", func(t *testing.T) {
		repo := &mockMFARepo{getMFAStatusErr: errors.New("db error")}
		svc := newTestService(repo, newMockRateLimiter(5))

		status, err := svc.GetStatus(context.Background(), "test-user")

		assert.Error(t, err)
		assert.Nil(t, status)
	})
}

func TestHashBackupCode(t *testing.T) {
	code := "abcd1234"
	expected := sha256.Sum256([]byte(code))
	expectedHex := hex.EncodeToString(expected[:])

	assert.Equal(t, expectedHex, hashBackupCode(code))
}

func TestGenerateBackupCodes(t *testing.T) {
	plaintext, hashed, err := generateBackupCodes("user-123", 10)

	require.NoError(t, err)
	assert.Len(t, plaintext, 10)
	assert.Len(t, hashed, 10)

	// All codes should be unique.
	seen := make(map[string]bool)
	for _, code := range plaintext {
		assert.Len(t, code, backupCodeLength)
		assert.False(t, seen[code], "duplicate backup code: %s", code)
		seen[code] = true
	}

	// Hashes should match.
	for i, code := range plaintext {
		expectedHash := hashBackupCode(code)
		assert.Equal(t, expectedHash, hashed[i].CodeHash)
		assert.Equal(t, "user-123", hashed[i].UserID)
		assert.False(t, hashed[i].Used)
		assert.NotEmpty(t, hashed[i].ID)
	}
}

func TestRandomCode(t *testing.T) {
	code, err := randomCode(8)
	require.NoError(t, err)
	assert.Len(t, code, 8)

	for _, c := range code {
		assert.Contains(t, backupCodeAlphabet, string(c))
	}

	// Two codes should (almost certainly) be different.
	code2, err := randomCode(8)
	require.NoError(t, err)
	assert.NotEqual(t, code, code2)
}

func TestTOTPRoundTrip(t *testing.T) {
	// Full enrollment → confirm → verify flow.
	repo := &mockMFARepo{getSecretErr: storage.ErrNotFound}
	limiter := newMockRateLimiter(5)
	svc := newTestService(repo, limiter)

	// Enroll.
	result, err := svc.EnrollTOTP(context.Background(), "test-user")
	require.NoError(t, err)

	// Confirm with valid TOTP code.
	code := generateValidCode(t, result.Secret)
	require.NoError(t, svc.ConfirmEnrollment(context.Background(), "test-user", code))

	// Verify with valid TOTP code.
	code2 := generateValidCode(t, result.Secret)
	require.NoError(t, svc.VerifyTOTP(context.Background(), "test-user", code2))

	// Verify backup code works.
	require.NoError(t, svc.VerifyBackupCode(context.Background(), "test-user", result.BackupCodes[0]))

	// Same backup code fails on second use.
	err = svc.VerifyBackupCode(context.Background(), "test-user", result.BackupCodes[0])
	assert.ErrorIs(t, err, ErrInvalidBackupCode)

	// Different backup code still works.
	require.NoError(t, svc.VerifyBackupCode(context.Background(), "test-user", result.BackupCodes[1]))

	// Disable MFA.
	require.NoError(t, svc.DisableMFA(context.Background(), "test-user"))
}
