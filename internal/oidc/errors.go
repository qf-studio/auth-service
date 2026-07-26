package oidc

import "errors"

// Sentinel errors returned by the Redis-backed stores in this package.
var (
	// ErrLoginRequestNotFound indicates the login request does not exist,
	// has expired, or has already been consumed.
	ErrLoginRequestNotFound = errors.New("oidc: login request not found")

	// ErrConsentRequestNotFound indicates the consent request does not
	// exist, has expired, or has already been consumed.
	ErrConsentRequestNotFound = errors.New("oidc: consent request not found")

	// ErrAuthorizationCodeNotFound indicates the authorization code does not
	// exist, has expired, or has already been redeemed.
	ErrAuthorizationCodeNotFound = errors.New("oidc: authorization code not found")
)
