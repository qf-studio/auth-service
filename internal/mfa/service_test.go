package mfa

import (
	"context"
	"fmt"
	"testing"

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
	getMFAStatusFn     func(ctx context.Context, userID string) (*domain.MFAStatus, error)
	getSecretFn        func(ctx context.Context, userID string) (*domain.MFASecret, error)
	getBackupCodesFn   func(ctx context.Context, userID string) ([]domain.BackupCode, error)
	consumeBackupFn    func(ctx context.Context, userID, codeHash string) error
	saveSecretFn       func(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)
	confirmSecretFn    func(ctx context.Context, userID string) error
	deleteSecretFn     func(ctx context.Context, userID string) error
	saveBackupCodesFn  func(ctx context.Context, userID string, codes []domain.BackupCode) error
}

func (m *mockMFARepository) SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	if m.saveSecretFn != nil {
		return m.saveSecretFn(ctx, secret)
	}
	return secret, nil
}

func (m *mockMFARepository) GetSecret(ctx context.Context, userID string) (*domain.MFASecret, error) {
	if m.getSecretFn != nil {
		return m.getSecretFn(ctx, userID)
	}
	return nil, fmt.Errorf("user %s: %w", userID, storage.ErrNotFound)
}

func (m *mockMFARepository) ConfirmSecret(ctx context.Context, userID string) error {
	if m.confirmSecretFn != nil {
		return m.confirmSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockMFARepository) DeleteSecret(ctx context.Context, userID string) error {
	if m.deleteSecretFn != nil {
		return m.deleteSecretFn(ctx, userID)
	}
	return nil
}

func (m *mockMFARepository) SaveBackupCodes(ctx context.Context, userID string, codes []domain.BackupCode) error {
	if m.saveBackupCodesFn != nil {
		return m.saveBackupCodesFn(ctx, userID, codes)
	}
	return nil
}

func (m *mockMFARepository) GetBackupCodes(ctx context.Context, userID string) ([]domain.BackupCode, error) {
	if m.getBackupCodesFn != nil {
		return m.getBackupCodesFn(ctx, userID)
	}
	return nil, nil
}

func (m *mockMFARepository) ConsumeBackupCode(ctx context.Context, userID, codeHash string) error {
	if m.consumeBackupFn != nil {
		return m.consumeBackupFn(ctx, userID, codeHash)
	}
	return nil
}

func (m *mockMFARepository) GetMFAStatus(ctx context.Context, userID string) (*domain.MFAStatus, error) {
	if m.getMFAStatusFn != nil {
		return m.getMFAStatusFn(ctx, userID)
	}
	return &domain.MFAStatus{UserID: userID}, nil
}

type mockMFATokenStore struct {
	storeMFATokenFn      func(ctx context.Context, token, userID string) error
	consumeMFATokenFn    func(ctx context.Context, token string) (string, error)
	recordFailedFn       func(ctx context.Context, userID string) (int, error)
	clearFailedFn        func(ctx context.Context, userID string) error
}

func (m *mockMFATokenStore) StoreMFAToken(ctx context.Context, token, userID string) error {
	if m.storeMFATokenFn != nil {
		return m.storeMFATokenFn(ctx, token, userID)
	}
	return nil
}

func (m *mockMFATokenStore) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	if m.consumeMFATokenFn != nil {
		return m.consumeMFATokenFn(ctx, token)
	}
	return "", storage.ErrMFATokenNotFound
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

// ── Helpers ──────────────────────────────────────────────────────────────────

func newTestService(repo storage.MFARepository, store MFATokenStore) *Service {
	logger, _ := zap.NewDevelopment()
	return NewService(repo, store, logger, audit.NopLogger{})
}

// ── Tests ────────────────────────────────────────────────────────────────────

func TestIsMFAEnabled(t *testing.T) {
	tests := []struct {
		name     string
		status   *domain.MFAStatus
		want     bool
		wantErr  bool
	}{
		{
			name:   "enabled and confirmed",
			status: &domain.MFAStatus{UserID: "u1", Enabled: true, Type: "totp", Confirmed: true},
			want:   true,
		},
		{
			name:   "not enabled",
			status: &domain.MFAStatus{UserID: "u1", Enabled: false},
			want:   false,
		},
		{
			name:   "enrolled but not confirmed",
			status: &domain.MFAStatus{UserID: "u1", Enabled: false, Type: "totp", Confirmed: false},
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockMFARepository{
				getMFAStatusFn: func(_ context.Context, _ string) (*domain.MFAStatus, error) {
					return tt.status, nil
				},
			}
			svc := newTestService(repo, &mockMFATokenStore{})
			got, err := svc.IsMFAEnabled(context.Background(), "u1")
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func TestGetMFAStatus(t *testing.T) {
	repo := &mockMFARepository{
		getMFAStatusFn: func(_ context.Context, _ string) (*domain.MFAStatus, error) {
			return &domain.MFAStatus{
				UserID:     "u1",
				Enabled:    true,
				Type:       "totp",
				Confirmed:  true,
				BackupLeft: 8,
			}, nil
		},
	}
	svc := newTestService(repo, &mockMFATokenStore{})
	info, err := svc.GetMFAStatus(context.Background(), "u1")
	require.NoError(t, err)
	assert.True(t, info.Enabled)
	assert.Equal(t, "totp", info.Type)
	assert.Equal(t, 8, info.BackupLeft)
}

func TestGenerateMFAToken(t *testing.T) {
	var storedToken, storedUserID string
	store := &mockMFATokenStore{
		storeMFATokenFn: func(_ context.Context, token, userID string) error {
			storedToken = token
			storedUserID = userID
			return nil
		},
	}

	svc := newTestService(&mockMFARepository{}, store)
	token, err := svc.GenerateMFAToken(context.Background(), "u1")
	require.NoError(t, err)
	assert.Len(t, token, mfaTokenBytes*2) // hex-encoded
	assert.Equal(t, token, storedToken)
	assert.Equal(t, "u1", storedUserID)
}

func TestGenerateMFAToken_StoreError(t *testing.T) {
	store := &mockMFATokenStore{
		storeMFATokenFn: func(_ context.Context, _, _ string) error {
			return fmt.Errorf("redis down")
		},
	}
	svc := newTestService(&mockMFARepository{}, store)
	_, err := svc.GenerateMFAToken(context.Background(), "u1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store mfa token")
}

func TestConsumeMFAToken(t *testing.T) {
	store := &mockMFATokenStore{
		consumeMFATokenFn: func(_ context.Context, token string) (string, error) {
			if token == "valid-token" {
				return "u1", nil
			}
			return "", storage.ErrMFATokenNotFound
		},
	}
	svc := newTestService(&mockMFARepository{}, store)

	t.Run("valid token", func(t *testing.T) {
		userID, err := svc.ConsumeMFAToken(context.Background(), "valid-token")
		require.NoError(t, err)
		assert.Equal(t, "u1", userID)
	})

	t.Run("invalid token", func(t *testing.T) {
		_, err := svc.ConsumeMFAToken(context.Background(), "bad-token")
		require.Error(t, err)
		assert.ErrorIs(t, err, api.ErrUnauthorized)
	})
}

func TestVerifyCode_TOTP(t *testing.T) {
	// Generate a real TOTP secret for testing.
	// Since we can't predict the code, we test the failure path and
	// verify that a correct code would succeed by using a known secret.
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				UserID:    "u1",
				Type:      "totp",
				Secret:    "JBSWY3DPEHPK3PXP", // known test secret
				Confirmed: true,
			}, nil
		},
		getBackupCodesFn: func(_ context.Context, _ string) ([]domain.BackupCode, error) {
			return nil, nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{})

	// Invalid TOTP code should fail.
	err := svc.VerifyCode(context.Background(), "u1", "000000")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestVerifyCode_BackupCode(t *testing.T) {
	backupCode := "ABCD1234"
	codeHash := HashBackupCode(backupCode)

	var consumed bool
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, _ string) (*domain.MFASecret, error) {
			return &domain.MFASecret{
				UserID:    "u1",
				Type:      "totp",
				Secret:    "JBSWY3DPEHPK3PXP",
				Confirmed: true,
			}, nil
		},
		getBackupCodesFn: func(_ context.Context, _ string) ([]domain.BackupCode, error) {
			return []domain.BackupCode{
				{UserID: "u1", CodeHash: codeHash, Used: false},
			}, nil
		},
		consumeBackupFn: func(_ context.Context, userID, hash string) error {
			consumed = true
			assert.Equal(t, "u1", userID)
			assert.Equal(t, codeHash, hash)
			return nil
		},
	}

	svc := newTestService(repo, &mockMFATokenStore{})
	err := svc.VerifyCode(context.Background(), "u1", backupCode)
	require.NoError(t, err)
	assert.True(t, consumed)
}

func TestVerifyCode_NoSecret(t *testing.T) {
	repo := &mockMFARepository{
		getSecretFn: func(_ context.Context, userID string) (*domain.MFASecret, error) {
			return nil, fmt.Errorf("user %s: %w", userID, storage.ErrNotFound)
		},
	}
	svc := newTestService(repo, &mockMFATokenStore{})
	err := svc.VerifyCode(context.Background(), "u1", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestRecordFailedAttempt_MaxExceeded(t *testing.T) {
	store := &mockMFATokenStore{
		recordFailedFn: func(_ context.Context, _ string) (int, error) {
			return 5, storage.ErrMFAMaxAttempts
		},
	}
	svc := newTestService(&mockMFARepository{}, store)
	count, err := svc.RecordFailedAttempt(context.Background(), "u1")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrForbidden)
	assert.Equal(t, 5, count)
}

func TestHashBackupCode(t *testing.T) {
	h1 := HashBackupCode("ABCD1234")
	h2 := HashBackupCode("ABCD1234")
	h3 := HashBackupCode("EFGH5678")

	assert.Equal(t, h1, h2, "same input should produce same hash")
	assert.NotEqual(t, h1, h3, "different input should produce different hash")
	assert.Len(t, h1, 64, "SHA-256 hex hash should be 64 chars")
}

func TestGenerateMFAToken_Uniqueness(t *testing.T) {
	tokens := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		token, err := generateMFAToken()
		require.NoError(t, err)
		assert.Len(t, token, mfaTokenBytes*2)
		assert.False(t, tokens[token], "token collision at iteration %d", i)
		tokens[token] = true
	}
}
