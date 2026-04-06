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

	// OAuth errors.
	ErrOAuthProviderNotSupported = errors.New("oauth provider not supported")
	ErrOAuthAccountAlreadyLinked = errors.New("oauth account already linked")
	ErrOAuthAccountNotFound      = errors.New("oauth account not found")
	ErrOAuthStateMismatch        = errors.New("oauth state mismatch")
	ErrOAuthCodeExchangeFailed   = errors.New("oauth code exchange failed")

	// GDPR / consent errors.
	ErrConsentNotFound            = errors.New("consent record not found")
	ErrConsentAlreadyGranted      = errors.New("consent already granted")
	ErrDeletionRequestNotFound    = errors.New("deletion request not found")
	ErrDeletionRequestExists      = errors.New("deletion request already exists")
	ErrDeletionRequestNotCancellable = errors.New("deletion request cannot be cancelled")
)
