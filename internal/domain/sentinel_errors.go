package domain

import "errors"

// Sentinel errors for domain-level error handling via errors.Is().
var (
	// User errors.
	ErrUserNotFound       = errors.New("user not found")
	ErrUserAlreadyExists  = errors.New("user already exists")
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrAccountLocked      = errors.New("account locked")
	ErrAccountSuspended   = errors.New("account suspended")

	// Token errors.
	ErrTokenExpired = errors.New("token expired")
	ErrTokenRevoked = errors.New("token revoked")
	ErrTokenInvalid = errors.New("token invalid")

	// Client errors.
	ErrClientNotFound  = errors.New("client not found")
	ErrClientSuspended = errors.New("client suspended")

	// Session errors.
	ErrSessionInactive = errors.New("session inactive due to inactivity")

	// Authorization errors.
	ErrInsufficientScope = errors.New("insufficient scope")
	ErrInsufficientRole  = errors.New("insufficient role")

	// MFA errors.
	ErrMFARequired    = errors.New("MFA verification required")
	ErrMFANotEnabled  = errors.New("MFA not enabled for user")
	ErrMFAAlreadyEnabled = errors.New("MFA already enabled for user")
	ErrInvalidTOTP    = errors.New("invalid TOTP code")
	ErrBackupCodeUsed = errors.New("backup code already used")
	ErrMFAMaxAttempts = errors.New("MFA max verification attempts exceeded")
)
