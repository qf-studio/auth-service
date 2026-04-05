package mfa

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// mfaTokenBytes is the number of random bytes in an MFA challenge token (32 bytes = 64 hex chars).
	mfaTokenBytes = 32

	// auditEventMFAChallenge is logged when an MFA challenge is issued during login.
	auditEventMFAChallenge = "mfa_challenge"

	// auditEventMFAVerifySuccess is logged after successful MFA verification.
	auditEventMFAVerifySuccess = "mfa_verify_success"

	// auditEventMFAVerifyFailure is logged after failed MFA verification.
	auditEventMFAVerifyFailure = "mfa_verify_failure"
)

// MFATokenStore abstracts the Redis-backed temporary MFA token operations.
type MFATokenStore interface {
	StoreMFAToken(ctx context.Context, token, userID string) error
	ConsumeMFAToken(ctx context.Context, token string) (string, error)
	RecordFailedAttempt(ctx context.Context, userID string) (int, error)
	ClearFailedAttempts(ctx context.Context, userID string) error
}

// Service implements MFA business logic: status checks, token generation,
// TOTP verification, and backup code verification.
type Service struct {
	repo   storage.MFARepository
	store  MFATokenStore
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewService creates a new MFA service.
func NewService(
	repo storage.MFARepository,
	store MFATokenStore,
	logger *zap.Logger,
	auditor audit.EventLogger,
) *Service {
	return &Service{
		repo:   repo,
		store:  store,
		logger: logger,
		audit:  auditor,
	}
}

// GetMFAStatus returns the MFA enrollment status for a user.
func (s *Service) GetMFAStatus(ctx context.Context, userID string) (*api.MFAStatusInfo, error) {
	status, err := s.repo.GetMFAStatus(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("get mfa status: %w", err)
	}
	return &api.MFAStatusInfo{
		Enabled:    status.Enabled,
		Type:       status.Type,
		BackupLeft: status.BackupLeft,
	}, nil
}

// IsMFAEnabled checks whether MFA is enabled and confirmed for a user.
func (s *Service) IsMFAEnabled(ctx context.Context, userID string) (bool, error) {
	status, err := s.repo.GetMFAStatus(ctx, userID)
	if err != nil {
		return false, fmt.Errorf("check mfa enabled: %w", err)
	}
	return status.Enabled, nil
}

// GenerateMFAToken creates a cryptographically random MFA challenge token,
// stores it in Redis with a 5-minute TTL, and returns the token.
func (s *Service) GenerateMFAToken(ctx context.Context, userID string) (string, error) {
	token, err := generateMFAToken()
	if err != nil {
		return "", fmt.Errorf("generate mfa token: %w", err)
	}

	if err := s.store.StoreMFAToken(ctx, token, userID); err != nil {
		return "", fmt.Errorf("store mfa token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     auditEventMFAChallenge,
		ActorID:  userID,
		TargetID: userID,
	})

	return token, nil
}

// ConsumeMFAToken atomically retrieves and deletes the MFA token from Redis.
// Returns the associated user ID.
func (s *Service) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	userID, err := s.store.ConsumeMFAToken(ctx, token)
	if err != nil {
		if errors.Is(err, storage.ErrMFATokenNotFound) {
			return "", fmt.Errorf("invalid or expired mfa token: %w", api.ErrUnauthorized)
		}
		return "", fmt.Errorf("consume mfa token: %w", err)
	}
	return userID, nil
}

// VerifyCode validates a TOTP code or backup code against the user's stored secret.
// Returns nil on success, or an error wrapping api.ErrUnauthorized on failure.
func (s *Service) VerifyCode(ctx context.Context, userID, code string) error {
	secret, err := s.repo.GetSecret(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("no mfa secret for user: %w", api.ErrUnauthorized)
		}
		return fmt.Errorf("get mfa secret: %w", err)
	}

	// Try TOTP first.
	if totp.Validate(code, secret.Secret) {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     auditEventMFAVerifySuccess,
			ActorID:  userID,
			TargetID: userID,
			Metadata: map[string]string{"method": "totp"},
		})
		return nil
	}

	// TOTP failed — try backup codes (8-char alphanumeric, stored as SHA-256 hashes).
	if s.tryBackupCode(ctx, userID, code) {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     auditEventMFAVerifySuccess,
			ActorID:  userID,
			TargetID: userID,
			Metadata: map[string]string{"method": "backup_code"},
		})
		return nil
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     auditEventMFAVerifyFailure,
		ActorID:  userID,
		TargetID: userID,
	})
	return fmt.Errorf("invalid mfa code: %w", api.ErrUnauthorized)
}

// RecordFailedAttempt increments the failed MFA attempt counter.
func (s *Service) RecordFailedAttempt(ctx context.Context, userID string) (int, error) {
	count, err := s.store.RecordFailedAttempt(ctx, userID)
	if err != nil {
		if errors.Is(err, storage.ErrMFAMaxAttempts) {
			return count, fmt.Errorf("too many failed mfa attempts: %w", api.ErrForbidden)
		}
		return count, fmt.Errorf("record failed attempt: %w", err)
	}
	return count, nil
}

// ClearFailedAttempts resets the failed attempt counter for a user.
func (s *Service) ClearFailedAttempts(ctx context.Context, userID string) error {
	return s.store.ClearFailedAttempts(ctx, userID)
}

// tryBackupCode attempts to consume a backup code by hashing the input
// and checking against stored unused codes.
func (s *Service) tryBackupCode(ctx context.Context, userID, code string) bool {
	codes, err := s.repo.GetBackupCodes(ctx, userID)
	if err != nil {
		s.logger.Error("failed to get backup codes", zap.String("user_id", userID), zap.Error(err))
		return false
	}

	codeHash := HashBackupCode(code)
	for _, c := range codes {
		if !c.Used && c.CodeHash == codeHash {
			if err := s.repo.ConsumeBackupCode(ctx, userID, codeHash); err != nil {
				s.logger.Error("failed to consume backup code", zap.String("user_id", userID), zap.Error(err))
				return false
			}
			return true
		}
	}
	return false
}

// generateMFAToken produces a cryptographically random hex-encoded token.
func generateMFAToken() (string, error) {
	b := make([]byte, mfaTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// HashBackupCode produces the SHA-256 hex hash of a backup code.
// Exported so enrollment code can use the same hashing.
func HashBackupCode(code string) string {
	h := sha256.Sum256([]byte(code))
	return hex.EncodeToString(h[:])
}

// Ensure *Service satisfies the domain.MFAStatus check (compile-time check not needed here,
// but the auth package defines its own narrow interface).
var _ interface {
	IsMFAEnabled(ctx context.Context, userID string) (bool, error)
	GenerateMFAToken(ctx context.Context, userID string) (string, error)
	ConsumeMFAToken(ctx context.Context, token string) (string, error)
	VerifyCode(ctx context.Context, userID, code string) error
	RecordFailedAttempt(ctx context.Context, userID string) (int, error)
	ClearFailedAttempts(ctx context.Context, userID string) error
} = (*Service)(nil)
