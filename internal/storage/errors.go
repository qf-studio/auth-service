package storage

import "errors"

// Repository-level sentinel errors used by storage implementations.
// Service layers wrap these to produce appropriate HTTP responses.
var (
	// ErrNotFound indicates the requested entity does not exist.
	ErrNotFound = errors.New("not found")

	// ErrDuplicateEmail indicates a user with the given email already exists.
	ErrDuplicateEmail = errors.New("duplicate email")

	// ErrInvalidCredentials indicates authentication failed (wrong email or password).
	// Services should return this for both "not found" and "wrong password" to prevent enumeration.
	ErrInvalidCredentials = errors.New("invalid credentials")

	// ErrAccountLocked indicates the user account is locked.
	ErrAccountLocked = errors.New("account locked")

	// ErrAccountSuspended indicates the user account has been soft-deleted.
	ErrAccountSuspended = errors.New("account suspended")

	// ErrTokenRevoked indicates the refresh token has already been revoked.
	ErrTokenRevoked = errors.New("token revoked")

	// ErrTokenExpired indicates the refresh token has expired.
	ErrTokenExpired = errors.New("token expired")

	// ErrAlreadyDeleted indicates the entity has already been soft-deleted.
	ErrAlreadyDeleted = errors.New("already deleted")

	// ErrDuplicateClient indicates a client with the given name already exists.
	ErrDuplicateClient = errors.New("duplicate client name")

	// ErrDuplicateMFA indicates the user already has an active MFA secret of this type.
	ErrDuplicateMFA = errors.New("duplicate mfa enrollment")

	// ErrMFATokenNotFound indicates the MFA token does not exist or has been consumed.
	ErrMFATokenNotFound = errors.New("mfa token not found")

	// ErrMFAMaxAttempts indicates the user has exceeded maximum MFA verification attempts.
	ErrMFAMaxAttempts = errors.New("mfa max attempts exceeded")

	// ErrDuplicateOAuthAccount indicates an OAuth account with the same provider and provider user ID already exists.
	ErrDuplicateOAuthAccount = errors.New("duplicate oauth account")
)
