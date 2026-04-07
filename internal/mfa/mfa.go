// Package mfa provides multi-factor authentication: TOTP enrollment,
// verification, backup codes, and admin management.
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

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// backupCodeBytes is the number of random bytes per backup code (8 bytes = 16 hex chars).
	backupCodeBytes = 8
)

// MFATokenStore abstracts temporary MFA token storage (Redis).
type MFATokenStore interface {
	StoreMFAToken(ctx context.Context, token, userID string) error
	ConsumeMFAToken(ctx context.Context, token string) (string, error)
	RecordFailedAttempt(ctx context.Context, userID string) (int, error)
	ClearFailedAttempts(ctx context.Context, userID string) error
}

// TokenIssuer abstracts token pair creation for completing MFA login.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
}

// Config holds MFA-specific settings.
type Config struct {
	Issuer          string // TOTP issuer name shown in authenticator apps
	Digits          int    // Number of digits (default 6)
	Period          uint   // TOTP period in seconds (default 30)
	BackupCodeCount int    // Number of backup codes to generate (default 10)
}

// DefaultConfig returns the default MFA configuration.
func DefaultConfig() Config {
	return Config{
		Issuer:          "QuantFlow Studio",
		Digits:          6,
		Period:          30,
		BackupCodeCount: 10,
	}
}

// Service implements MFA business logic.
type Service struct {
	cfg    Config
	repo   storage.MFARepository
	tokens MFATokenStore
	issuer TokenIssuer
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewService creates a new MFA service.
func NewService(
	cfg Config,
	repo storage.MFARepository,
	tokens MFATokenStore,
	issuer TokenIssuer,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		cfg:    cfg,
		repo:   repo,
		tokens: tokens,
		issuer: issuer,
		logger: logger,
		audit:  auditor,
	}
}

// InitiateEnrollment generates a new TOTP secret for the user.
// The secret is stored unconfirmed until the user verifies a code.
func (s *Service) InitiateEnrollment(ctx context.Context, userID, email string) (*api.MFAEnrollmentResult, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	otpDigits := otp.DigitsSix
	if s.cfg.Digits == 8 {
		otpDigits = otp.DigitsEight
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      s.cfg.Issuer,
		AccountName: email,
		Period:      s.cfg.Period,
		Digits:      otpDigits,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		return nil, fmt.Errorf("generate totp key: %w", err)
	}

	secret := &domain.MFASecret{
		ID:        uuid.New().String(),
		TenantID:  tenantID,
		UserID:    userID,
		Type:      "totp",
		Secret:    key.Secret(),
		Confirmed: false,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if _, err := s.repo.SaveSecret(ctx, secret); err != nil {
		if errors.Is(err, storage.ErrDuplicateMFA) {
			return nil, fmt.Errorf("mfa already enrolled: %w", api.ErrConflict)
		}
		return nil, fmt.Errorf("save mfa secret: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_enrollment_initiated",
		ActorID:  userID,
		TargetID: userID,
	})

	return &api.MFAEnrollmentResult{
		Secret: key.Secret(),
		URI:    key.URL(),
	}, nil
}

// ConfirmEnrollment validates a TOTP code against the unconfirmed secret,
// confirms it, and generates backup codes.
func (s *Service) ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	secret, err := s.repo.GetSecret(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("no pending enrollment: %w", api.ErrNotFound)
		}
		return nil, fmt.Errorf("get mfa secret: %w", err)
	}

	if secret.Confirmed {
		return nil, fmt.Errorf("mfa already confirmed: %w", api.ErrConflict)
	}

	if !s.validateTOTP(secret.Secret, code) {
		return nil, fmt.Errorf("invalid totp code: %w", api.ErrUnauthorized)
	}

	if err := s.repo.ConfirmSecret(ctx, tenantID, userID); err != nil {
		return nil, fmt.Errorf("confirm mfa secret: %w", err)
	}

	// Generate and store backup codes.
	plainCodes, hashedCodes, err := s.generateBackupCodes(tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("generate backup codes: %w", err)
	}

	if err := s.repo.SaveBackupCodes(ctx, tenantID, userID, hashedCodes); err != nil {
		return nil, fmt.Errorf("save backup codes: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_enrollment_confirmed",
		ActorID:  userID,
		TargetID: userID,
	})

	return plainCodes, nil
}

// VerifyTOTP validates a TOTP code for a user with confirmed MFA.
func (s *Service) VerifyTOTP(ctx context.Context, userID, code string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	secret, err := s.repo.GetSecret(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("mfa not enrolled: %w", api.ErrNotFound)
		}
		return fmt.Errorf("get mfa secret: %w", err)
	}

	if !secret.Confirmed {
		return fmt.Errorf("mfa not confirmed: %w", api.ErrNotFound)
	}

	if !s.validateTOTP(secret.Secret, code) {
		if _, err := s.tokens.RecordFailedAttempt(ctx, userID); err != nil {
			if errors.Is(err, storage.ErrMFAMaxAttempts) {
				return fmt.Errorf("too many failed attempts: %w", api.ErrForbidden)
			}
			s.logger.Error("failed to record mfa attempt", zap.Error(err))
		}
		return fmt.Errorf("invalid totp code: %w", api.ErrUnauthorized)
	}

	if err := s.tokens.ClearFailedAttempts(ctx, userID); err != nil {
		s.logger.Error("failed to clear mfa attempts", zap.String("user_id", userID), zap.Error(err))
	}

	return nil
}

// VerifyBackupCode validates and consumes a backup code for a user.
func (s *Service) VerifyBackupCode(ctx context.Context, userID, code string) error {
	tenantID := domain.TenantIDFromContext(ctx)
	codeHash := hashBackupCode(code)

	if err := s.repo.ConsumeBackupCode(ctx, tenantID, userID, codeHash); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			if _, err := s.tokens.RecordFailedAttempt(ctx, userID); err != nil {
				if errors.Is(err, storage.ErrMFAMaxAttempts) {
					return fmt.Errorf("too many failed attempts: %w", api.ErrForbidden)
				}
				s.logger.Error("failed to record mfa attempt", zap.Error(err))
			}
			return fmt.Errorf("invalid backup code: %w", api.ErrUnauthorized)
		}
		return fmt.Errorf("consume backup code: %w", err)
	}

	if err := s.tokens.ClearFailedAttempts(ctx, userID); err != nil {
		s.logger.Error("failed to clear mfa attempts", zap.String("user_id", userID), zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_backup_code_used",
		ActorID:  userID,
		TargetID: userID,
	})

	return nil
}

// CompleteMFALogin verifies the MFA token and TOTP/backup code, then issues tokens.
func (s *Service) CompleteMFALogin(ctx context.Context, mfaToken, code, codeType string) (*api.AuthResult, error) {
	userID, err := s.tokens.ConsumeMFAToken(ctx, mfaToken)
	if err != nil {
		if errors.Is(err, storage.ErrMFATokenNotFound) {
			return nil, fmt.Errorf("invalid or expired mfa token: %w", api.ErrUnauthorized)
		}
		return nil, fmt.Errorf("consume mfa token: %w", err)
	}

	switch codeType {
	case "totp", "":
		if err := s.VerifyTOTP(ctx, userID, code); err != nil {
			return nil, err
		}
	case "backup":
		if err := s.VerifyBackupCode(ctx, userID, code); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported code type %q: %w", codeType, api.ErrUnauthorized)
	}

	// Issue full token pair now that MFA is verified.
	result, err := s.issuer.IssueTokenPair(ctx, userID, nil, nil, domain.ClientTypeUser)
	if err != nil {
		return nil, fmt.Errorf("issue tokens after mfa: %w", err)
	}
	result.UserID = userID

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "mfa_login_success",
		ActorID:  userID,
		TargetID: userID,
	})

	return result, nil
}

// Disable removes MFA for a user (deletes secret and backup codes).
func (s *Service) Disable(ctx context.Context, userID string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	if err := s.repo.DeleteSecret(ctx, tenantID, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("mfa not enrolled: %w", api.ErrNotFound)
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

// GetStatus returns the MFA status for a user.
func (s *Service) GetStatus(ctx context.Context, userID string) (*api.MFAStatusResponse, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	status, err := s.repo.GetMFAStatus(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("get mfa status: %w", err)
	}
	return &api.MFAStatusResponse{
		Enabled:    status.Enabled,
		Type:       status.Type,
		Confirmed:  status.Confirmed,
		BackupLeft: status.BackupLeft,
	}, nil
}

// GenerateMFAToken creates a short-lived token for the MFA challenge flow.
func (s *Service) GenerateMFAToken(ctx context.Context, userID string) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate mfa token: %w", err)
	}
	token := hex.EncodeToString(b)

	if err := s.tokens.StoreMFAToken(ctx, token, userID); err != nil {
		return "", fmt.Errorf("store mfa token: %w", err)
	}

	return token, nil
}

// IsMFAEnabled checks if the user has confirmed MFA enrollment.
func (s *Service) IsMFAEnabled(ctx context.Context, userID string) (bool, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	status, err := s.repo.GetMFAStatus(ctx, tenantID, userID)
	if err != nil {
		return false, fmt.Errorf("check mfa status: %w", err)
	}
	return status.Enabled && status.Confirmed, nil
}

// validateTOTP checks a TOTP code against the secret.
func (s *Service) validateTOTP(secret, code string) bool {
	valid, err := totp.ValidateCustom(code, secret, time.Now().UTC(), totp.ValidateOpts{
		Period:    s.cfg.Period,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		s.logger.Error("totp validation error", zap.Error(err))
		return false
	}
	return valid
}

// generateBackupCodes creates the configured number of random backup codes.
// Returns both plaintext codes (for the user) and hashed domain objects (for storage).
func (s *Service) generateBackupCodes(tenantID uuid.UUID, userID string) ([]string, []domain.BackupCode, error) {
	count := s.cfg.BackupCodeCount
	if count <= 0 {
		count = 10
	}

	plain := make([]string, 0, count)
	hashed := make([]domain.BackupCode, 0, count)

	for i := 0; i < count; i++ {
		b := make([]byte, backupCodeBytes)
		if _, err := rand.Read(b); err != nil {
			return nil, nil, fmt.Errorf("generate backup code: %w", err)
		}

		code := formatBackupCode(hex.EncodeToString(b))
		plain = append(plain, code)

		hashed = append(hashed, domain.BackupCode{
			ID:        uuid.New().String(),
			TenantID:  tenantID,
			UserID:    userID,
			CodeHash:  hashBackupCode(code),
			Used:      false,
			CreatedAt: time.Now().UTC(),
		})
	}

	return plain, hashed, nil
}

// formatBackupCode formats a hex string as xxxx-xxxx-xxxx-xxxx for readability.
func formatBackupCode(hex string) string {
	hex = strings.ReplaceAll(hex, "-", "")
	var parts []string
	for i := 0; i < len(hex); i += 4 {
		end := i + 4
		if end > len(hex) {
			end = len(hex)
		}
		parts = append(parts, hex[i:end])
	}
	return strings.Join(parts, "-")
}

// hashBackupCode returns the SHA-256 hex digest of a backup code (normalized).
func hashBackupCode(code string) string {
	normalized := strings.ReplaceAll(strings.ToLower(strings.TrimSpace(code)), "-", "")
	h := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(h[:])
}
