package mfa

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

type mockMFARepository struct {
	saveSecretFn     func(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)
	getSecretFn      func(ctx context.Context, userID string) (*domain.MFASecret, error)
	confirmSecretFn  func(ctx context.Context, userID string) error
	deleteSecretFn   func(ctx context.Context, userID string) error
	saveBackupFn     func(ctx context.Context, userID string, codes []domain.BackupCode) error
	getBackupFn      func(ctx context.Context, userID string) ([]domain.BackupCode, error)
	consumeBackupFn  func(ctx context.Context, userID, codeHash string) error
	getMFAStatusFn   func(ctx context.Context, userID string) (*domain.MFAStatus, error)
}

func (m *mockMFARepository) SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	if m.saveSecretFn != nil {
		return m.saveSecretFn(ctx, secret)
	}
	return secret, nil
}

func (m *mockMFARepository) GetSecret(ctx context.Context, _ uuid.UUID, userID string) (*domain.MFASecret, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, userID)
	}
	return nil, storage.ErrNotFound
}

func (m *mockMFARepository) ConfirmSecret(ctx context.Context, _ uuid.UUID, userID string) error {
	if m.confirmSecretFn != nil {
		return m.confirmSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockMFARepository) DeleteSecret(ctx context.Context, _ uuid.UUID, userID string) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockMFARepository) SaveBackupCodes(ctx context.Context, _ uuid.UUID, userID string, codes []domain.BackupCode) error {
	if m.saveBackupFn != nil {
		return m.saveBackupFn(ctx, userID, codes)
	}
	return nil
}

func (m *mockMFARepository) GetBackupCodes(ctx context.Context, _ uuid.UUID, userID string) ([]domain.BackupCode, error) {
	if m.getBackupFn != nil {
		return m.getBackupFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockMFARepository) ConsumeBackupCode(ctx context.Context, _ uuid.UUID, userID, codeHash string) error {
	if m.consumeBackupFn != nil {
		return m.consumeBackupFn(ctx, userID, codeHash)
	}
	return nil
}

func (m *mockMFARepository) GetMFAStatus(ctx context.Context, _ uuid.UUID, userID string) (*domain.MFAStatus, error) {
	if m.getMFAStatusFn != nil {
		return m.getMFAStatusFn(ctx, userID)
	}
	return &domain.MFAStatus{UserID: userID}, nil
}

type mockMFATokenStore struct {
	storeFn          func(ctx context.Context, token, userID string) error
	consumeFn        func(ctx context.Context, token string) (string, error)
	recordFailedFn   func(ctx context.Context, userID string) (int, error)
	clearFailedFn    func(ctx context.Context, userID string) error
}

func (m *mockMFATokenStore) StoreMFAToken(ctx context.Context, token, userID string) error {
	if m.storeFn != nil {
		return m.storeFn(ctx, token, userID)
	}
	return nil
}

func (m *mockMFATokenStore) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	if m.consumeFn != nil {
		return m.consumeFn(ctx, token)
	}
	return "user-1", nil
}

func (m *mockMFATokenStore) RecordFailedAttempt(ctx context.Context, userID string) (int, error) {
	if m.recordFailedFn != nil {
		return m.recordFailedFn(ctx, userID)
	}
	return 1, nil
}

func (m *mockMFATokenStore) ClearFailedAttempts(ctx context.Context, userID string) error {
	if m.clearFailedFn != nil {
		return m.clearFailedFn(ctx, userID)
	}
	return nil
}

type mockTokenIssuer struct {
	issueTokenPairFn func(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType) (*api.AuthResult, error)
}

func (m *mockTokenIssuer) IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, ct domain.ClientType) (*api.AuthResult, error) {
	if m.issueTokenPairFn != nil {
		return m.issueTokenPairFn(ctx, subject, roles, scopes, ct)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_test-access",
		RefreshToken: "qf_rt_test-refresh",
		TokenType:    "Bearer",
		ExpiresIn:    900,
	}, nil
}

// ── Test helpers ─────────────────────────────────────────────────────────────

func newTestService(repo *mockMFARepository, tokens *mockMFATokenStore, issuer *mockTokenIssuer) *Service {
	logger, _ := zap.NewDevelopment()
	return NewService(
		DefaultConfig(),
		repo,
		tokens,
		issuer,
		logger,
		audit.NopLogger{},
	)
}

// ── Enrollment Tests ─────────────────────────────────────────────────────────

func TestInitiateEnrollment_Success(t *testing.T) {
	var savedSecret *domain.MFASecret
	repo := &mockMFARepository{
		saveSecretFn: func(_ context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
			savedSecret = secret
			return secret, nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})

	result, err := svc.InitiateEnrollment(context.Background(), "user-1", "alice@example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotEmpty(t, result.Secret)
	assert.Contains(t, result.URI, "otpauth://totp/")
	assert.Contains(t, result.URI, "QuantFlow")

	require.NotNil(t, savedSecret)
	assert.Equal(t, "user-1", savedSecret.UserID)
	assert.Equal(t, "totp", savedSecret.Type)
	assert.False(t, savedSecret.Confirmed)
}

func TestInitiateEnrollment_DuplicateReturnsConflict(t *testing.T) {
	repo := &mockMFARepository{
		saveSecretFn: func(_ context.Context, _ *domain.MFASecret) (*domain.MFASecret, error) {
			return nil, storage.ErrDuplicateMFA
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	_, err := svc.InitiateEnrollment(context.Background(), "user-1", "alice@example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// ── Confirm Enrollment Tests ─────────────────────────────────────────────────

func TestConfirmEnrollment_Success(t *testing.T) {
	// Generate a real TOTP secret for testing
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "alice@test.com",
	})
	require.NoError(t, err)

	// Generate a valid code
	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	var confirmed bool
	var backupsSaved bool
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				ID:        "secret-1",
				UserID:    "user-1",
				Type:      "totp",
				Secret:    key.Secret(),
				Confirmed: false,
			}, nil
		},
		confirmSecretFn: func(_ context.Context, _ string) error {
			confirmed = true
			return nil
		},
		saveBackupFn: func(_ context.Context, _ string, codes []domain.BackupCode) error {
			backupsSaved = true
			assert.Len(t, codes, 10, "expected 10 backup codes")
			return nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})

	backupCodes, err := svc.ConfirmEnrollment(context.Background(), "user-1", code)
	require.NoError(t, err)
	assert.Len(t, backupCodes, 10)
	assert.True(t, confirmed)
	assert.True(t, backupsSaved)
}

func TestConfirmEnrollment_InvalidCode(t *testing.T) {
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				ID:        "secret-1",
				UserID:    "user-1",
				Type:      "totp",
				Secret:    "JBSWY3DPEHPK3PXP", // known test secret
				Confirmed: false,
			}, nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestConfirmEnrollment_AlreadyConfirmed(t *testing.T) {
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				ID:        "secret-1",
				UserID:    "user-1",
				Type:      "totp",
				Secret:    "JBSWY3DPEHPK3PXP",
				Confirmed: true,
			}, nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestConfirmEnrollment_NoPendingEnrollment(t *testing.T) {
	repo := &mockMFARepository{} // default returns ErrNotFound

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	_, err := svc.ConfirmEnrollment(context.Background(), "user-1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ── TOTP Verification Tests ──────────────────────────────────────────────────

func TestVerifyTOTP_Success(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "alice@test.com",
	})
	require.NoError(t, err)

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	var cleared bool
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				Secret:    key.Secret(),
				Confirmed: true,
			}, nil
		},
	}
	tokens := &mockMFATokenStore{
		clearFailedFn: func(_ context.Context, _ string) error {
			cleared = true
			return nil
		},
	}

	svc := newTestService(repo, tokens, &mockTokenIssuer{})
	err = svc.VerifyTOTP(context.Background(), "user-1", code)
	require.NoError(t, err)
	assert.True(t, cleared, "expected failed attempts to be cleared")
}

func TestVerifyTOTP_InvalidCode(t *testing.T) {
	var failedRecorded bool
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				Secret:    "JBSWY3DPEHPK3PXP",
				Confirmed: true,
			}, nil
		},
	}
	tokens := &mockMFATokenStore{
		recordFailedFn: func(_ context.Context, _ string) (int, error) {
			failedRecorded = true
			return 1, nil
		},
	}

	svc := newTestService(repo, tokens, &mockTokenIssuer{})
	err := svc.VerifyTOTP(context.Background(), "user-1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
	assert.True(t, failedRecorded)
}

func TestVerifyTOTP_MaxAttemptsExceeded(t *testing.T) {
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				Secret:    "JBSWY3DPEHPK3PXP",
				Confirmed: true,
			}, nil
		},
	}
	tokens := &mockMFATokenStore{
		recordFailedFn: func(_ context.Context, _ string) (int, error) {
			return 5, storage.ErrMFAMaxAttempts
		},
	}

	svc := newTestService(repo, tokens, &mockTokenIssuer{})
	err := svc.VerifyTOTP(context.Background(), "user-1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrForbidden)
}

// ── Backup Code Tests ────────────────────────────────────────────────────────

func TestVerifyBackupCode_Success(t *testing.T) {
	var consumed bool
	repo := &mockMFARepository{
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			consumed = true
			return nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	err := svc.VerifyBackupCode(context.Background(), "user-1", "abcd-1234-efgh-5678")
	require.NoError(t, err)
	assert.True(t, consumed)
}

func TestVerifyBackupCode_Invalid(t *testing.T) {
	repo := &mockMFARepository{
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			return storage.ErrNotFound
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	err := svc.VerifyBackupCode(context.Background(), "user-1", "invalid-code")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

// ── Complete MFA Login Tests ─────────────────────────────────────────────────

func TestCompleteMFALogin_Success(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "Test",
		AccountName: "alice@test.com",
	})
	require.NoError(t, err)

	code, err := totp.GenerateCode(key.Secret(), time.Now())
	require.NoError(t, err)

	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				Secret:    key.Secret(),
				Confirmed: true,
			}, nil
		},
	}
	tokenStore := &mockMFATokenStore{
		consumeFn: func(_ context.Context, token string) (string, error) {
			if token == "valid-mfa-token" {
				return "user-1", nil
			}
			return "", storage.ErrMFATokenNotFound
		},
	}

	svc := newTestService(repo, tokenStore, &mockTokenIssuer{})

	result, err := svc.CompleteMFALogin(context.Background(), "valid-mfa-token", code, "totp")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "qf_at_test-access", result.AccessToken)
	assert.Equal(t, "user-1", result.UserID)
}

func TestCompleteMFALogin_InvalidToken(t *testing.T) {
	tokenStore := &mockMFATokenStore{
		consumeFn: func(_ context.Context, _ string) (string, error) {
			return "", storage.ErrMFATokenNotFound
		},
	}

	svc := newTestService(&mockMFARepository{}, tokenStore, &mockTokenIssuer{})
	_, err := svc.CompleteMFALogin(context.Background(), "bad-token", "123456", "totp")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestCompleteMFALogin_BackupCode(t *testing.T) {
	var consumed bool
	repo := &mockMFARepository{
		consumeBackupFn: func(_ context.Context, _, _ string) error {
			consumed = true
			return nil
		},
	}
	tokenStore := &mockMFATokenStore{
		consumeFn: func(_ context.Context, _ string) (string, error) {
			return "user-1", nil
		},
	}

	svc := newTestService(repo, tokenStore, &mockTokenIssuer{})
	result, err := svc.CompleteMFALogin(context.Background(), "mfa-token", "abcd-1234-efgh-5678", "backup")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, consumed)
	assert.Equal(t, "user-1", result.UserID)
}

// ── Disable Tests ────────────────────────────────────────────────────────────

func TestDisable_Success(t *testing.T) {
	var deleted bool
	repo := &mockMFARepository{
		deleteSecretFn: func(_ context.Context, _ string) error {
			deleted = true
			return nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	err := svc.Disable(context.Background(), "user-1")
	require.NoError(t, err)
	assert.True(t, deleted)
}

func TestDisable_NotEnrolled(t *testing.T) {
	repo := &mockMFARepository{
		deleteSecretFn: func(_ context.Context, _ string) error {
			return storage.ErrNotFound
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	err := svc.Disable(context.Background(), "user-1")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// ── Status Tests ─────────────────────────────────────────────────────────────

func TestGetStatus_Success(t *testing.T) {
	repo := &mockMFARepository{
		getMFAStatusFn: func(_ context.Context, userID string) (*domain.MFAStatus, error) {
			return &domain.MFAStatus{
				UserID:     userID,
				Enabled:    true,
				Type:       "totp",
				Confirmed:  true,
				BackupLeft: 8,
			}, nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
	status, err := svc.GetStatus(context.Background(), "user-1")
	require.NoError(t, err)
	assert.True(t, status.Enabled)
	assert.Equal(t, "totp", status.Type)
	assert.True(t, status.Confirmed)
	assert.Equal(t, 8, status.BackupLeft)
}

// ── IsMFAEnabled Tests ───────────────────────────────────────────────────────

func TestIsMFAEnabled(t *testing.T) {
	tests := []struct {
		name     string
		status   *domain.MFAStatus
		expected bool
	}{
		{
			name:     "enabled and confirmed",
			status:   &domain.MFAStatus{Enabled: true, Confirmed: true},
			expected: true,
		},
		{
			name:     "enabled but not confirmed",
			status:   &domain.MFAStatus{Enabled: true, Confirmed: false},
			expected: false,
		},
		{
			name:     "not enabled",
			status:   &domain.MFAStatus{Enabled: false, Confirmed: false},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockMFARepository{
				getMFAStatusFn: func(_ context.Context, _ string) (*domain.MFAStatus, error) {
					return tt.status, nil
				},
			}
			svc := newTestService(repo, &mockMFATokenStore{}, &mockTokenIssuer{})
			enabled, err := svc.IsMFAEnabled(context.Background(), "user-1")
			require.NoError(t, err)
			assert.Equal(t, tt.expected, enabled)
		})
	}
}

// ── GenerateMFAToken Tests ───────────────────────────────────────────────────

func TestGenerateMFAToken_Success(t *testing.T) {
	var storedToken string
	tokens := &mockMFATokenStore{
		storeFn: func(_ context.Context, token, userID string) error {
			storedToken = token
			assert.Equal(t, "user-1", userID)
			return nil
		},
	}

	svc := newTestService(&mockMFARepository{}, tokens, &mockTokenIssuer{})
	token, err := svc.GenerateMFAToken(context.Background(), "user-1")
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Len(t, token, 64) // 32 bytes = 64 hex chars
	assert.Equal(t, storedToken, token)
}

func TestGenerateMFAToken_StoreError(t *testing.T) {
	tokens := &mockMFATokenStore{
		storeFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("redis down")
		},
	}

	svc := newTestService(&mockMFARepository{}, tokens, &mockTokenIssuer{})
	_, err := svc.GenerateMFAToken(context.Background(), "user-1")
	require.Error(t, err)
}

// ── Backup Code Format Tests ─────────────────────────────────────────────────

func TestFormatBackupCode(t *testing.T) {
	result := formatBackupCode("abcdef1234567890")
	assert.Equal(t, "abcd-ef12-3456-7890", result)
}

func TestHashBackupCode_Normalization(t *testing.T) {
	// Same code in different formats should hash the same
	hash1 := hashBackupCode("abcd-1234-efgh-5678")
	hash2 := hashBackupCode("ABCD-1234-EFGH-5678")
	hash3 := hashBackupCode("abcd1234efgh5678")
	hash4 := hashBackupCode("  ABCD-1234-EFGH-5678  ")

	assert.Equal(t, hash1, hash2, "case normalization")
	assert.Equal(t, hash1, hash3, "dash normalization")
	assert.Equal(t, hash1, hash4, "whitespace normalization")
}
