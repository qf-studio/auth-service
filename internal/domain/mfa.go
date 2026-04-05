package domain

import "time"

// MFASecret represents a TOTP MFA secret bound to a user account.
type MFASecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Algorithm       string // e.g. "SHA1", "SHA256", "SHA512"
	Digits          int    // typically 6 or 8
	Period          int    // time step in seconds, typically 30
	Confirmed       bool
	CreatedAt       time.Time
}

// BackupCode represents a single-use recovery code for MFA bypass.
type BackupCode struct {
	ID        string
	UserID    string
	CodeHash  string
	Used      bool
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MFASetupRequest is the input for initiating MFA enrollment.
type MFASetupRequest struct {
	UserID string `json:"user_id" binding:"required"`
}

// MFASetupResponse is the output after MFA enrollment initiation.
type MFASetupResponse struct {
	Secret     string   `json:"secret"`      // plaintext TOTP secret (shown once)
	QRCodeURI  string   `json:"qr_code_uri"` // otpauth:// URI for QR generation
	BackupCodes []string `json:"backup_codes"` // plaintext backup codes (shown once)
}

// MFAVerifyRequest is the input for confirming MFA setup or validating a TOTP code.
type MFAVerifyRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required,len=6|len=8"`
}

// MFADisableRequest is the input for disabling MFA on an account.
type MFADisableRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required"` // TOTP or backup code for verification
}

// MFABackupVerifyRequest is the input for validating a backup code.
type MFABackupVerifyRequest struct {
	UserID string `json:"user_id" binding:"required"`
	Code   string `json:"code" binding:"required"`
}

// MFAStatusResponse reports the current MFA state for a user.
type MFAStatusResponse struct {
	Enabled          bool `json:"enabled"`
	Confirmed        bool `json:"confirmed"`
	BackupCodesLeft  int  `json:"backup_codes_left"`
}
