// Package oidc provides domain types and Redis-backed ephemeral stores for
// the OIDC/OAuth2 authorization code flow: login challenge -> consent
// challenge -> one-time authorization code. See GH-431 for the full provider
// design (Hydra-style external login/consent UI); this package covers the
// storage building blocks consumed by that provider implementation.
package oidc

import "time"

// LoginRequest represents a pending authorization request waiting for the
// login UI to authenticate a subject. It is created when GET /oauth/authorize
// is hit by an unauthenticated caller and resolved (accepted or rejected)
// via the admin login-request API.
type LoginRequest struct {
	Challenge           string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	RequestedAt         time.Time
	ExpiresAt           time.Time
}

// ConsentRequest represents a pending authorization request waiting for the
// consent UI to approve the requested scopes on behalf of an already
// authenticated subject. It is created once the corresponding LoginRequest
// has been accepted.
type ConsentRequest struct {
	Challenge           string
	Subject             string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	State               string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}

// AuthorizationCode represents a one-time authorization code issued after
// consent has been granted. It is exchanged exactly once for a token pair at
// POST /oauth/token.
type AuthorizationCode struct {
	Code                string
	Subject             string
	ClientID            string
	RedirectURI         string
	Scopes              []string
	Nonce               string
	CodeChallenge       string
	CodeChallengeMethod string
	AuthTime            time.Time
	ExpiresAt           time.Time
}
