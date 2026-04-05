package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockMFARepository is a configurable mock for storage.MFARepository.
type MockMFARepository struct {
	SaveSecretFn      func(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)
	GetSecretFn       func(ctx context.Context, userID string) (*domain.MFASecret, error)
	ConfirmSecretFn   func(ctx context.Context, userID string) error
	DeleteSecretFn    func(ctx context.Context, userID string) error
	SaveBackupCodesFn func(ctx context.Context, userID string, codes []domain.BackupCode) error
	GetBackupCodesFn  func(ctx context.Context, userID string) ([]domain.BackupCode, error)
	ConsumeBackupCodeFn func(ctx context.Context, userID, codeHash string) error
	GetMFAStatusFn    func(ctx context.Context, userID string) (*domain.MFAStatus, error)
}

// SaveSecret delegates to SaveSecretFn.
func (m *MockMFARepository) SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error) {
	return m.SaveSecretFn(ctx, secret)
}

// GetSecret delegates to GetSecretFn.
func (m *MockMFARepository) GetSecret(ctx context.Context, userID string) (*domain.MFASecret, error) {
	return m.GetSecretFn(ctx, userID)
}

// ConfirmSecret delegates to ConfirmSecretFn.
func (m *MockMFARepository) ConfirmSecret(ctx context.Context, userID string) error {
	return m.ConfirmSecretFn(ctx, userID)
}

// DeleteSecret delegates to DeleteSecretFn.
func (m *MockMFARepository) DeleteSecret(ctx context.Context, userID string) error {
	return m.DeleteSecretFn(ctx, userID)
}

// SaveBackupCodes delegates to SaveBackupCodesFn.
func (m *MockMFARepository) SaveBackupCodes(ctx context.Context, userID string, codes []domain.BackupCode) error {
	return m.SaveBackupCodesFn(ctx, userID, codes)
}

// GetBackupCodes delegates to GetBackupCodesFn.
func (m *MockMFARepository) GetBackupCodes(ctx context.Context, userID string) ([]domain.BackupCode, error) {
	return m.GetBackupCodesFn(ctx, userID)
}

// ConsumeBackupCode delegates to ConsumeBackupCodeFn.
func (m *MockMFARepository) ConsumeBackupCode(ctx context.Context, userID, codeHash string) error {
	return m.ConsumeBackupCodeFn(ctx, userID, codeHash)
}

// GetMFAStatus delegates to GetMFAStatusFn.
func (m *MockMFARepository) GetMFAStatus(ctx context.Context, userID string) (*domain.MFAStatus, error) {
	return m.GetMFAStatusFn(ctx, userID)
}
