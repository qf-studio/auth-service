package domain

import "time"

// TokenClaims holds the parsed and validated claims from an access token.
// It is populated by AuthMiddleware and stored in the Gin context under
// the key "claims". Handlers retrieve it via middleware.GetClaims.
type TokenClaims struct {
	// Subject is the user ID (for user tokens) or client ID (for system tokens).
	Subject string

	// Roles are the roles granted to this subject (e.g., "admin", "user").
	// Role checks use any-of semantics: access is granted if the subject holds
	// at least one of the required roles.
	Roles []string

	// Scopes are the OAuth 2.1 scopes granted to system clients
	// (e.g., "read:users", "write:tokens"). Scope checks use all-of semantics:
	// all required scopes must be present.
	Scopes []string

	// ClientType identifies the kind of entity that owns this token.
	// See ClientTypeUser, ClientTypeService, ClientTypeAgent in client.go.
	ClientType ClientType

	// TokenID is the unique identifier (jti) used for revocation checks
	// against the Redis blocklist.
	TokenID string

	// ExpiresAt is the token expiration time from the JWT exp claim.
	// Zero value means not set (e.g., when parsing non-JWT tokens).
	ExpiresAt time.Time

	// IssuedAt is the token issuance time from the JWT iat claim.
	// Zero value means not set.
	IssuedAt time.Time

	// DPoPThumbprint is the JWK thumbprint from the cnf.jkt claim.
	// When set, the token is DPoP-bound and requests must include a
	// valid DPoP proof whose public key matches this thumbprint.
	// Empty string means the token is a plain Bearer token.
	DPoPThumbprint string
}
