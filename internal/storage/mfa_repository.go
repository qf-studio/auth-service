package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MFARepository defines persistence operations for MFA secrets and backup codes.
type MFARepository interface {
	// SaveSecret creates or replaces the MFA secret for a user+method pair.
	SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)

	// GetSecret retrieves the MFA secret for a user and method.
	GetSecret(ctx context.Context, userID string, method domain.MFAMethod) (*domain.MFASecret, error)

	// ConfirmSecret marks an MFA secret as confirmed (user completed verification).
	ConfirmSecret(ctx context.Context, userID string, method domain.MFAMethod) error

	// DeleteSecret removes an MFA secret for a user and method.
	DeleteSecret(ctx context.Context, userID string, method domain.MFAMethod) error

	// SaveBackupCodes replaces all backup codes for a user (hashed).
	SaveBackupCodes(ctx context.Context, userID string, codeHashes []string) error

	// GetBackupCodes returns all unused backup codes for a user.
	GetBackupCodes(ctx context.Context, userID string) ([]*domain.MFABackupCode, error)

	// ConsumeBackupCode marks a single backup code as used. Returns ErrNotFound
	// if no unused code matches the given hash.
	ConsumeBackupCode(ctx context.Context, userID string, codeHash string) error

	// GetMFAStatus returns the aggregate MFA status for a user.
	GetMFAStatus(ctx context.Context, userID string) (*domain.MFAStatus, error)
}
