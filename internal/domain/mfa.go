package domain

import (
	"errors"
	"time"
)

// MFA method types.
const (
	MFAMethodTOTP       = "totp"
	MFAMethodBackupCode = "backup_code"
)

// TOTP defaults per RFC 6238.
const (
	TOTPAlgorithm = "SHA1"
	TOTPDigits    = 6
	TOTPPeriod    = 30
	TOTPSecretLen = 20 // 160 bits
	TOTPSkew      = 1  // ±1 step window
)

// Backup code defaults.
const (
	BackupCodeCount  = 10
	BackupCodeLength = 8
)

// MFASecret represents a TOTP secret enrollment for a user.
type MFASecret struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Secret    string    `json:"secret"`     // Base32-encoded TOTP secret
	Algorithm string    `json:"algorithm"`  // e.g. "SHA1"
	Digits    int       `json:"digits"`     // e.g. 6
	Period    int       `json:"period"`     // e.g. 30
	Confirmed bool      `json:"confirmed"`  // Whether user confirmed enrollment
	CreatedAt time.Time `json:"created_at"`
}

// BackupCode represents a hashed backup/recovery code.
type BackupCode struct {
	ID        string     `json:"id"`
	UserID    string     `json:"user_id"`
	CodeHash  string     `json:"code_hash"` // SHA-256 hash
	Used      bool       `json:"used"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// TOTPEnrollmentResult is returned when a user starts TOTP enrollment.
type TOTPEnrollmentResult struct {
	Secret         string   `json:"secret"`          // Base32-encoded secret
	ProvisioningURI string  `json:"provisioning_uri"` // otpauth:// URI for QR code
	BackupCodes    []string `json:"backup_codes"`     // Plaintext codes (shown once)
}

// MFA sentinel errors.
var (
	ErrMFAAlreadyEnabled  = errors.New("mfa already enabled")
	ErrMFANotEnabled      = errors.New("mfa not enabled")
	ErrMFANotConfirmed    = errors.New("mfa enrollment not confirmed")
	ErrInvalidTOTPCode    = errors.New("invalid totp code")
	ErrInvalidBackupCode  = errors.New("invalid backup code")
	ErrBackupCodeUsed     = errors.New("backup code already used")
	ErrNoBackupCodes      = errors.New("no backup codes available")
)
