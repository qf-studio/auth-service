// Package mfa provides multi-factor authentication: TOTP enrollment,
// verification, and backup code management.
package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// totpIssuer is the issuer name displayed in authenticator apps.
	totpIssuer = "QuantFlow Studio"

	// totpSecretSize is the TOTP secret length in bytes (160 bits per RFC 4226).
	totpSecretSize = 20

	// totpDigits is the number of OTP digits.
	totpDigits = 6

	// totpPeriod is the time step in seconds.
	totpPeriod = 30

	// backupCodeCount is the number of backup codes generated per enrollment.
	backupCodeCount = 10

	// backupCodeLength is the character length of each plaintext backup code.
	backupCodeLength = 8

	// backupCodeAlphabet contains the allowed characters for backup codes.
	backupCodeAlphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// Sentinel errors returned by the MFA service.
var (
	ErrMFAAlreadyEnrolled = errors.New("mfa already enrolled")
	ErrMFANotEnrolled     = errors.New("mfa not enrolled")
	ErrMFANotConfirmed    = errors.New("mfa not confirmed")
	ErrInvalidTOTP        = errors.New("invalid totp code")
	ErrInvalidBackupCode  = errors.New("invalid backup code")
	ErrMaxAttempts        = errors.New("max verification attempts exceeded")
)

// MFARepo is the subset of storage.MFARepository used by Service.
type MFARepo interface {
	SaveSecret(ctx context.Context, secret *domain.MFASecret) (*domain.MFASecret, error)
	GetSecret(ctx context.Context, userID string) (*domain.MFASecret, error)
	ConfirmSecret(ctx context.Context, userID string) error
	DeleteSecret(ctx context.Context, userID string) error
	SaveBackupCodes(ctx context.Context, userID string, codes []domain.BackupCode) error
	GetBackupCodes(ctx context.Context, userID string) ([]domain.BackupCode, error)
	ConsumeBackupCode(ctx context.Context, userID, codeHash string) error
	GetMFAStatus(ctx context.Context, userID string) (*domain.MFAStatus, error)
}

// RateLimiter is the subset of storage.RedisMFAStore used by Service for
// failed-attempt tracking.
type RateLimiter interface {
	RecordFailedAttempt(ctx context.Context, userID string) (int, error)
	ClearFailedAttempts(ctx context.Context, userID string) error
}

// EnrollmentResult contains the data returned when a user enrolls in TOTP MFA.
type EnrollmentResult struct {
	Secret      string   // base32-encoded TOTP secret
	QRCodeURI   string   // otpauth:// URI for QR code generation
	BackupCodes []string // plaintext backup codes (shown once)
}

// Service implements the core MFA business logic.
type Service struct {
	repo    MFARepo
	limiter RateLimiter
	logger  *zap.Logger
	audit   audit.EventLogger
}

// NewService creates a new MFA service.
func NewService(
	repo MFARepo,
	limiter RateLimiter,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		repo:    repo,
		limiter: limiter,
		logger:  logger,
		audit:   auditor,
	}
}

// EnrollTOTP generates a new TOTP secret and backup codes for the user.
// The enrollment is not active until ConfirmEnrollment is called with a valid code.
func (s *Service) EnrollTOTP(ctx context.Context, userID string) (*EnrollmentResult, error) {
	// Check if user already has an active (non-deleted) MFA secret.
	existing, err := s.repo.GetSecret(ctx, userID)
	if err != nil && !errors.Is(err, storage.ErrNotFound) {
		return nil, fmt.Errorf("check existing mfa: %w", err)
	}
	if existing != nil {
		return nil, ErrMFAAlreadyEnrolled
	}

	// Generate TOTP key using pquerna/otp.
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      totpIssuer,
		AccountName: userID,
		SecretSize:  totpSecretSize,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
		Period:      totpPeriod,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	// Generate backup codes.
	plaintextCodes, hashedCodes, err := generateBackupCodes(userID, backupCodeCount)
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	// Persist the secret (unconfirmed).
	now := time.Now().UTC()
	secret := &domain.MFASecret{
		ID:        uuid.New().String(),
		UserID:    userID,
		Type:      "totp",
		Secret:    key.Secret(),
		Confirmed: false,
		CreatedAt: now,
		UpdatedAt: now,
	}

	if _, err := s.repo.SaveSecret(ctx, secret); err != nil {
		return nil, fmt.Errorf("save mfa secret: %w", err)
	}

	// Persist hashed backup codes.
	if err := s.repo.SaveBackupCodes(ctx, userID, hashedCodes); err != nil {
		return nil, fmt.Errorf("save backup codes: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_enroll_start",
		ActorID:  userID,
		TargetID: userID,
	})

	return &EnrollmentResult{
		Secret:      key.Secret(),
		QRCodeURI:   key.URL(),
		BackupCodes: plaintextCodes,
	}, nil
}

// ConfirmEnrollment activates MFA after the user provides a valid TOTP code,
// proving they have configured their authenticator app.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) error {
	secret, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get mfa secret: %w", err)
	}

	if secret.Confirmed {
		return ErrMFAAlreadyEnrolled
	}

	if !validateTOTP(secret.Secret, code) {
		return ErrInvalidTOTP
	}

	if err := s.repo.ConfirmSecret(ctx, userID); err != nil {
		return fmt.Errorf("confirm mfa secret: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_enroll_confirm",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// VerifyTOTP validates a TOTP code during login. It enforces rate limiting
// via the RateLimiter and clears failed attempts on success.
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	secret, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get mfa secret: %w", err)
	}

	if !secret.Confirmed {
		return ErrMFANotConfirmed
	}

	if !validateTOTP(secret.Secret, code) {
		if _, rateLimitErr := s.limiter.RecordFailedAttempt(ctx, userID); rateLimitErr != nil {
			if errors.Is(rateLimitErr, storage.ErrMFAMaxAttempts) {
				return ErrMaxAttempts
			}
			s.logger.Error("failed to record mfa attempt", zap.Error(rateLimitErr))
		}
		return ErrInvalidTOTP
	}

	// Clear failed attempts on success.
	if err := s.limiter.ClearFailedAttempts(ctx, userID); err != nil {
		s.logger.Error("failed to clear mfa attempts", zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_verify_success",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// VerifyBackupCode validates and consumes a single-use backup code.
// Rate limiting applies the same as TOTP verification.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, code string) error {
	secret, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("get mfa secret: %w", err)
	}

	if !secret.Confirmed {
		return ErrMFANotConfirmed
	}

	codeHash := hashBackupCode(strings.ToLower(strings.TrimSpace(code)))

	if err := s.repo.ConsumeBackupCode(ctx, userID, codeHash); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			if _, rateLimitErr := s.limiter.RecordFailedAttempt(ctx, userID); rateLimitErr != nil {
				if errors.Is(rateLimitErr, storage.ErrMFAMaxAttempts) {
					return ErrMaxAttempts
				}
				s.logger.Error("failed to record mfa attempt", zap.Error(rateLimitErr))
			}
			return ErrInvalidBackupCode
		}
		return fmt.Errorf("consume backup code: %w", err)
	}

	// Clear failed attempts on success.
	if err := s.limiter.ClearFailedAttempts(ctx, userID); err != nil {
		s.logger.Error("failed to clear mfa attempts", zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_backup_code_used",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// GetStatus returns the MFA enrollment status for a user.
func (s *Service) GetStatus(ctx context.Context, userID string) (*domain.MFAStatus, error) {
	status, err := s.repo.GetMFAStatus(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get mfa status: %w", err)
	}
	return status, nil
}

// DisableMFA soft-deletes the user's MFA secret (deactivates MFA).
func (s *Service) DisableMFA(ctx context.Context, userID string) error {
	if err := s.repo.DeleteSecret(ctx, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return ErrMFANotEnrolled
		}
		return fmt.Errorf("delete mfa secret: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_disabled",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// validateTOTP checks a TOTP code against the stored secret.
func validateTOTP(secret, code string) bool {
	valid, _ := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
		Period:    totpPeriod,
		Skew:     1, // allow ±1 time step (±30s drift)
	})
	return valid
}

// hashBackupCode returns the SHA-256 hex digest of a backup code.
func hashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// generateBackupCodes creates n random backup codes and their SHA-256 hashes.
func generateBackupCodes(userID string, n int) (plaintext []string, hashed []domain.BackupCode, err error) {
	plaintext = make([]string, n)
	hashed = make([]domain.BackupCode, n)
	now := time.Now().UTC()

	for i := 0; i < n; i++ {
		code, err := randomCode(backupCodeLength)
		if err != nil {
			return nil, nil, fmt.Errorf("generate backup code %d: %w", i, err)
		}
		plaintext[i] = code
		hashed[i] = domain.BackupCode{
			ID:        uuid.New().String(),
			UserID:    userID,
			CodeHash:  hashBackupCode(code),
			Used:      false,
			CreatedAt: now,
		}
	}
	return plaintext, hashed, nil
}

// randomCode generates a cryptographically random alphanumeric string of length n.
func randomCode(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	for i := range b {
		b[i] = backupCodeAlphabet[int(b[i])%len(backupCodeAlphabet)]
	}
	return string(b), nil
}
