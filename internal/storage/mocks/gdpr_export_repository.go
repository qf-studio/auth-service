package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockGDPRExportRepository is a configurable mock for storage.GDPRExportRepository.
type MockGDPRExportRepository struct {
	GetUserDataFn                   func(ctx context.Context, userID string) (*domain.User, error)
	GetOAuthAccountsFn              func(ctx context.Context, userID string) ([]domain.OAuthAccount, error)
	GetRefreshTokensFn              func(ctx context.Context, userID string) ([]domain.RefreshTokenRecord, error)
	GetConsentRecordsFn             func(ctx context.Context, userID string) ([]domain.ConsentRecord, error)
	SoftDeleteUserFn                func(ctx context.Context, userID string) error
	DeleteOAuthAccountsFn           func(ctx context.Context, userID string) error
	DeleteRefreshTokensFn           func(ctx context.Context, userID string) error
	AnonymizeAuditLogsFn            func(ctx context.Context, userID string) error
	DeleteExpiredSoftDeletedUsersFn func(ctx context.Context, retentionDays int) (int64, error)
	DeleteExpiredRefreshTokensFn    func(ctx context.Context, retentionDays int) (int64, error)
}

// GetUserData delegates to GetUserDataFn.
func (m *MockGDPRExportRepository) GetUserData(ctx context.Context, userID string) (*domain.User, error) {
	return m.GetUserDataFn(ctx, userID)
}

// GetOAuthAccounts delegates to GetOAuthAccountsFn.
func (m *MockGDPRExportRepository) GetOAuthAccounts(ctx context.Context, userID string) ([]domain.OAuthAccount, error) {
	return m.GetOAuthAccountsFn(ctx, userID)
}

// GetRefreshTokens delegates to GetRefreshTokensFn.
func (m *MockGDPRExportRepository) GetRefreshTokens(ctx context.Context, userID string) ([]domain.RefreshTokenRecord, error) {
	return m.GetRefreshTokensFn(ctx, userID)
}

// GetConsentRecords delegates to GetConsentRecordsFn.
func (m *MockGDPRExportRepository) GetConsentRecords(ctx context.Context, userID string) ([]domain.ConsentRecord, error) {
	return m.GetConsentRecordsFn(ctx, userID)
}

// SoftDeleteUser delegates to SoftDeleteUserFn.
func (m *MockGDPRExportRepository) SoftDeleteUser(ctx context.Context, userID string) error {
	return m.SoftDeleteUserFn(ctx, userID)
}

// DeleteOAuthAccounts delegates to DeleteOAuthAccountsFn.
func (m *MockGDPRExportRepository) DeleteOAuthAccounts(ctx context.Context, userID string) error {
	return m.DeleteOAuthAccountsFn(ctx, userID)
}

// DeleteRefreshTokens delegates to DeleteRefreshTokensFn.
func (m *MockGDPRExportRepository) DeleteRefreshTokens(ctx context.Context, userID string) error {
	return m.DeleteRefreshTokensFn(ctx, userID)
}

// AnonymizeAuditLogs delegates to AnonymizeAuditLogsFn.
func (m *MockGDPRExportRepository) AnonymizeAuditLogs(ctx context.Context, userID string) error {
	return m.AnonymizeAuditLogsFn(ctx, userID)
}

// DeleteExpiredSoftDeletedUsers delegates to DeleteExpiredSoftDeletedUsersFn.
func (m *MockGDPRExportRepository) DeleteExpiredSoftDeletedUsers(ctx context.Context, retentionDays int) (int64, error) {
	return m.DeleteExpiredSoftDeletedUsersFn(ctx, retentionDays)
}

// DeleteExpiredRefreshTokens delegates to DeleteExpiredRefreshTokensFn.
func (m *MockGDPRExportRepository) DeleteExpiredRefreshTokens(ctx context.Context, retentionDays int) (int64, error) {
	return m.DeleteExpiredRefreshTokensFn(ctx, retentionDays)
}
