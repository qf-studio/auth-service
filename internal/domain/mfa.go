package domain

import "time"

// MFA algorithm constants.
const (
	TOTPAlgorithmSHA1 = "SHA1"
	TOTPDefaultDigits = 6
	TOTPDefaultPeriod = 30
	BackupCodeCount   = 10
	BackupCodeLength  = 8
)

// MFAStatus represents the state of a user's MFA enrollment.
type MFAStatus string

const (
	MFAStatusDisabled    MFAStatus = "disabled"
	MFAStatusPending     MFAStatus = "pending"
	MFAStatusEnabled     MFAStatus = "enabled"
)

// MFASecret represents a TOTP secret bound to a user account.
type MFASecret struct {
	ID              string
	UserID          string
	EncryptedSecret string
	Algorithm       string
	Digits          int
	Period          int
	Confirmed       bool
	CreatedAt       time.Time
	UpdatedAt       time.Time
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

// --- MFA request/response structs ---

// TOTPEnrollmentRequest is the validated request body for starting TOTP enrollment.
type TOTPEnrollmentRequest struct {
	// No fields required — enrollment is initiated by the authenticated user.
}

// TOTPEnrollmentResponse is the response returned when TOTP enrollment starts.
type TOTPEnrollmentResponse struct {
	Secret    string `json:"secret"`
	OTPAuthURI string `json:"otpauth_uri"`
	QRCode    string `json:"qr_code,omitempty"`
}

// TOTPVerifyRequest is the validated request body for confirming TOTP enrollment
// or verifying a TOTP code during login.
type TOTPVerifyRequest struct {
	Code string `json:"code" validate:"required,len=6,numeric"`
}

// MFAVerifyLoginRequest is the validated request body for completing a login
// that requires MFA verification. The MFAToken is the temporary challenge
// token issued during the initial login step.
type MFAVerifyLoginRequest struct {
	MFAToken string `json:"mfa_token" validate:"required"`
	Code     string `json:"code"      validate:"required"`
}
