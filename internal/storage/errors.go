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

	// ErrDuplicateAPIKey indicates an API key with the given name already exists for the client.
	ErrDuplicateAPIKey = errors.New("duplicate api key name")
)
