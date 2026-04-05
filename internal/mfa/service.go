// Package mfa provides multi-factor authentication: TOTP, WebAuthn, backup codes (Phase 2).
package mfa

import (
	"fmt"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Service orchestrates MFA enrollment, confirmation, and verification flows.
// It is a pure logic layer with no database dependencies — storage is handled
// by the caller passing domain structs in and receiving results back.
type Service struct {
	issuer string // Service name for provisioning URI (e.g. "QuantFlow Studio")
}

// NewService creates an MFA service with the given issuer name.
func NewService(issuer string) *Service {
	return &Service{issuer: issuer}
}

// StartEnrollment generates a new TOTP secret and backup codes for the user.
// The returned result contains the secret, provisioning URI, and plaintext
// backup codes. The caller must persist these and show the codes to the user.
func (s *Service) StartEnrollment(accountName string) (*domain.TOTPEnrollmentResult, error) {
	secret, err := GenerateSecret()
	if err != nil {
		return nil, fmt.Errorf("start enrollment: %w", err)
	}

	uri, err := GenerateProvisioningURI(secret, s.issuer, accountName)
	if err != nil {
		return nil, fmt.Errorf("start enrollment: %w", err)
	}

	backupCodes, err := GenerateBackupCodes()
	if err != nil {
		return nil, fmt.Errorf("start enrollment: %w", err)
	}

	return &domain.TOTPEnrollmentResult{
		Secret:          secret,
		ProvisioningURI: uri,
		BackupCodes:     backupCodes,
	}, nil
}

// ConfirmEnrollment validates the TOTP code against the secret to confirm
// that the user has successfully set up their authenticator app.
func (s *Service) ConfirmEnrollment(secret, code string) error {
	if !ValidateCode(secret, code) {
		return domain.ErrInvalidTOTPCode
	}
	return nil
}

// VerifyTOTP checks a TOTP code against the user's confirmed secret.
func (s *Service) VerifyTOTP(secret string, confirmed bool, code string) error {
	if !confirmed {
		return domain.ErrMFANotConfirmed
	}
	if !ValidateCode(secret, code) {
		return domain.ErrInvalidTOTPCode
	}
	return nil
}

// VerifyBackupCode checks a plaintext backup code against a list of hashed codes.
// Returns the index of the matched code so the caller can mark it as used.
// Only unused codes are checked.
func (s *Service) VerifyBackupCode(code string, backupCodes []domain.BackupCode) (int, error) {
	if len(backupCodes) == 0 {
		return -1, domain.ErrNoBackupCodes
	}

	for i, bc := range backupCodes {
		if bc.Used {
			continue
		}
		if VerifyBackupCode(code, bc.CodeHash) {
			return i, nil
		}
	}

	return -1, domain.ErrInvalidBackupCode
}

// HashBackupCodes takes plaintext codes and returns domain.BackupCode structs
// with SHA-256 hashes. The caller should persist these.
func (s *Service) HashBackupCodes(userID string, codes []string) []domain.BackupCode {
	now := time.Now()
	result := make([]domain.BackupCode, len(codes))
	for i, code := range codes {
		result[i] = domain.BackupCode{
			UserID:    userID,
			CodeHash:  HashBackupCode(code),
			Used:      false,
			CreatedAt: now,
		}
	}
	return result
}
