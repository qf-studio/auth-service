package authclient

import "errors"

// Sentinel errors returned by Client methods.
var (
	// ErrTokenInvalid indicates the token is expired, revoked, or malformed.
	ErrTokenInvalid = errors.New("authclient: token invalid")

	// ErrUnauthenticated indicates the server rejected the request as
	// unauthenticated (gRPC Unauthenticated status).
	ErrUnauthenticated = errors.New("authclient: unauthenticated")

	// ErrPermissionDenied indicates the RBAC policy does not allow the
	// requested action.
	ErrPermissionDenied = errors.New("authclient: permission denied")
)
