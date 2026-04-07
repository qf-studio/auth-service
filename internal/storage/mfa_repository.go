package storage

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MFARepository defines the persistence operations for MFA secrets and backup codes.
type MFARepository interface {
	// SaveSecret creates or replaces the MFA secret for a user.
	SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)

	// GetSecret retrieves the active (non-deleted) MFA secret for a user.
	// Returns ErrNotFound if the user has no active secret.
	GetSecret(ctx context.Context, tenantID uuid.UUID, userID string) (*domain.MFASecret, error)

	// ConfirmSecret marks the user's MFA secret as confirmed.
	// Returns ErrNotFound if no active secret exists.
	ConfirmSecret(ctx context.Context, tenantID uuid.UUID, userID string) error

	// DeleteSecret soft-deletes the user's active MFA secret.
	// Returns ErrNotFound if no active secret exists.
	DeleteSecret(ctx context.Context, tenantID uuid.UUID, userID string) error

	// SaveBackupCodes stores a set of hashed backup codes for a user,
	// replacing any existing unused codes.
	SaveBackupCodes(ctx context.Context, tenantID uuid.UUID, userID string, codes []domain.BackupCode) error

	// GetBackupCodes returns all backup codes for a user (both used and unused).
	GetBackupCodes(ctx context.Context, tenantID uuid.UUID, userID string) ([]domain.BackupCode, error)

	// ConsumeBackupCode marks a backup code as used. Returns ErrNotFound
	// if no unused code with the given hash exists.
	ConsumeBackupCode(ctx context.Context, tenantID uuid.UUID, userID, codeHash string) error

	// GetMFAStatus returns the MFA enrollment status for a user.
	GetMFAStatus(ctx context.Context, tenantID uuid.UUID, userID string) (*domain.MFAStatus, error)
}
