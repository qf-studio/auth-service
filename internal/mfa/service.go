// Package mfa provides multi-factor authentication: TOTP enrollment/verification
// and single-use backup codes.
package mfa

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"
)

// Sentinel errors for MFA operations.
var (
	ErrMFANotEnabled    = errors.New("mfa not enabled for user")
	ErrMFAAlreadyActive = errors.New("mfa already active for user")
	ErrNotConfirmed     = errors.New("mfa enrollment not confirmed")
	ErrInvalidTOTP      = errors.New("invalid totp code")
	ErrBackupCodeUsed   = errors.New("backup code already used")
	ErrBackupCodeInvalid = errors.New("invalid backup code")
	ErrEnrollmentNotFound = errors.New("no pending mfa enrollment")
)

// MFAStatus represents the current MFA state for a user.
type MFAStatus struct {
	Enabled   bool
	Confirmed bool
	Method    string // "totp"
}

// EnrollmentResult is returned when a user starts TOTP enrollment.
type EnrollmentResult struct {
	Secret     string // base32-encoded secret (for manual entry)
	OTPAuthURL string // otpauth:// URI (for QR code generation)
}

// Repository defines the storage operations required by the MFA service.
// Implementations live in internal/storage (per project convention).
type Repository interface {
	// GetMFAStatus returns the MFA state for a user, or ErrMFANotEnabled if none exists.
	GetMFAStatus(ctx context.Context, userID string) (*MFAStatus, error)

	// SaveSecret stores an unconfirmed TOTP secret for a user.
	SaveSecret(ctx context.Context, userID, encryptedSecret, algorithm string, digits, period int) error

	// GetSecret returns the encrypted TOTP secret for a user.
	// Returns ErrMFANotEnabled if no secret exists.
	GetSecret(ctx context.Context, userID string) (encryptedSecret string, confirmed bool, err error)

	// ConfirmSecret marks the TOTP secret as confirmed (enrollment complete).
	ConfirmSecret(ctx context.Context, userID string) error

	// DeleteSecret removes the TOTP secret for a user.
	DeleteSecret(ctx context.Context, userID string) error

	// SaveBackupCodes stores hashed backup codes for a user, replacing any existing ones.
	SaveBackupCodes(ctx context.Context, userID string, codeHashes []string) error

	// GetBackupCodes returns all backup code hashes and their used status.
	GetBackupCodes(ctx context.Context, userID string) ([]BackupCodeRecord, error)

	// ConsumeBackupCode marks a backup code as used. Returns ErrBackupCodeInvalid
	// if no matching unused code exists.
	ConsumeBackupCode(ctx context.Context, userID, codeHash string) error
}

// BackupCodeRecord represents a stored backup code.
type BackupCodeRecord struct {
	CodeHash string
	Used     bool
}

// Service orchestrates TOTP enrollment/verification and backup codes.
type Service struct {
	repo   Repository
	logger *zap.Logger
	issuer string // TOTP issuer name (e.g., "QuantFlow Studio")
}

// NewService creates a new MFA service.
func NewService(repo Repository, logger *zap.Logger, issuer string) *Service {
	return &Service{
		repo:   repo,
		logger: logger,
		issuer: issuer,
	}
}

// EnrollTOTP starts TOTP enrollment for a user. Generates a secret and returns
// the otpauth:// URI for QR code display. The enrollment is not active until
// ConfirmEnrollment is called with a valid code.
func (s *Service) EnrollTOTP(ctx context.Context, userID, accountName string) (*EnrollmentResult, error) {
	// Check if MFA is already active.
	status, err := s.repo.GetMFAStatus(ctx, userID)
	if err != nil && !errors.Is(err, ErrMFANotEnabled) {
		return nil, fmt.Errorf("get mfa status: %w", err)
	}
	if status != nil && status.Confirmed {
		return nil, ErrMFAAlreadyActive
	}

	// Generate TOTP secret.
	secret, url, err := generateTOTPSecret(s.issuer, accountName)
	if err != nil {
		return nil, fmt.Errorf("generate totp secret: %w", err)
	}

	// Store unconfirmed secret.
	if err := s.repo.SaveSecret(ctx, userID, secret, "SHA1", totpDigits, totpPeriod); err != nil {
		return nil, fmt.Errorf("save secret: %w", err)
	}

	s.logger.Info("mfa enrollment started", zap.String("user_id", userID))

	return &EnrollmentResult{
		Secret:     secret,
		OTPAuthURL: url,
	}, nil
}

// ConfirmEnrollment validates the TOTP code against the pending secret and,
// if valid, marks the enrollment as confirmed and generates backup codes.
// Returns the plaintext backup codes (caller must display them once).
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	secret, confirmed, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, ErrMFANotEnabled) {
			return nil, ErrEnrollmentNotFound
		}
		return nil, fmt.Errorf("get secret: %w", err)
	}
	if confirmed {
		return nil, ErrMFAAlreadyActive
	}

	// Validate the code against the unconfirmed secret.
	if !validateTOTPCode(secret, code) {
		return nil, ErrInvalidTOTP
	}

	// Mark as confirmed.
	if err := s.repo.ConfirmSecret(ctx, userID); err != nil {
		return nil, fmt.Errorf("confirm secret: %w", err)
	}

	// Generate and store backup codes.
	plaintextCodes, hashes := generateBackupCodes(backupCodeCount)
	if err := s.repo.SaveBackupCodes(ctx, userID, hashes); err != nil {
		return nil, fmt.Errorf("save backup codes: %w", err)
	}

	s.logger.Info("mfa enrollment confirmed", zap.String("user_id", userID))

	return plaintextCodes, nil
}

// VerifyTOTP validates a TOTP code for a user with confirmed MFA.
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	secret, confirmed, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if !confirmed {
		return ErrNotConfirmed
	}

	if !validateTOTPCode(secret, code) {
		s.logger.Info("mfa verification failed", zap.String("user_id", userID))
		return ErrInvalidTOTP
	}

	s.logger.Info("mfa verification succeeded", zap.String("user_id", userID))
	return nil
}

// VerifyBackupCode validates and consumes a single-use backup code.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, code string) error {
	// Check MFA is enabled.
	secret, confirmed, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		return fmt.Errorf("get secret: %w", err)
	}
	if !confirmed || secret == "" {
		return ErrMFANotEnabled
	}

	hash := hashBackupCode(code)

	if err := s.repo.ConsumeBackupCode(ctx, userID, hash); err != nil {
		if errors.Is(err, ErrBackupCodeInvalid) {
			s.logger.Info("backup code verification failed", zap.String("user_id", userID))
			return ErrBackupCodeInvalid
		}
		return fmt.Errorf("consume backup code: %w", err)
	}

	s.logger.Info("backup code consumed", zap.String("user_id", userID))
	return nil
}

// DisableMFA removes the TOTP secret and all backup codes for a user.
func (s *Service) DisableMFA(ctx context.Context, userID string) error {
	// Verify MFA is currently enabled.
	status, err := s.repo.GetMFAStatus(ctx, userID)
	if err != nil {
		return fmt.Errorf("get mfa status: %w", err)
	}
	if status == nil || !status.Enabled {
		return ErrMFANotEnabled
	}

	if err := s.repo.DeleteSecret(ctx, userID); err != nil {
		return fmt.Errorf("delete secret: %w", err)
	}

	s.logger.Info("mfa disabled", zap.String("user_id", userID))
	return nil
}
