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

	// Password policy errors.
	ErrPasswordExpired  = errors.New("password expired")
	ErrPasswordReused   = errors.New("password was previously used")
	ErrPasswordTooShort = errors.New("password too short")
	ErrPasswordTooLong  = errors.New("password too long")

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

	// RAR (RFC 9396) errors.
	ErrRARTypeMissing      = errors.New("authorization type is required")
	ErrRARTypeInvalid      = errors.New("authorization type format is invalid")
	ErrRARTypeNotAllowed   = errors.New("authorization type not allowed for client")
	ErrRARTooManyLocations = errors.New("too many locations in authorization detail")
	ErrRARTooManyActions   = errors.New("too many actions in authorization detail")
	ErrRARTooManyDataTypes = errors.New("too many datatypes in authorization detail")

	// OAuth errors.
	ErrOAuthProviderNotSupported = errors.New("oauth provider not supported")
	ErrOAuthAccountAlreadyLinked = errors.New("oauth account already linked")
	ErrOAuthAccountNotFound      = errors.New("oauth account not found")
	ErrOAuthStateMismatch        = errors.New("oauth state mismatch")
	ErrOAuthCodeExchangeFailed   = errors.New("oauth code exchange failed")

	// SAML errors.
	ErrSAMLResponseInvalid      = errors.New("saml response invalid")
	ErrSAMLAssertionExpired     = errors.New("saml assertion expired")
	ErrSAMLSignatureInvalid     = errors.New("saml signature invalid")
	ErrSAMLIdPNotConfigured     = errors.New("saml idp not configured")
	ErrSAMLIdentityNotFound     = errors.New("saml identity not found")
	ErrSAMLIdentityAlreadyLinked = errors.New("saml identity already linked")
	ErrSAMLRequestIDMismatch    = errors.New("saml request id mismatch")
)
