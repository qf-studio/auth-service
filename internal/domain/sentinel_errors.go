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
	ErrOAuthAccountNotFound    = errors.New("oauth account not found")
	ErrOAuthAccountAlreadyLinked = errors.New("oauth account already linked")
	ErrOAuthProviderUnsupported = errors.New("unsupported oauth provider")
	ErrOAuthStateMismatch       = errors.New("oauth state mismatch")
	ErrOAuthCodeExchangeFailed  = errors.New("oauth code exchange failed")
)
