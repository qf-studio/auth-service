package oidc

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
)

const (
	// challengeIDBytes is the number of random bytes for login/consent
	// challenge IDs (32 bytes = 256 bits).
	challengeIDBytes = 32

	// authCodeBytes is the number of random bytes for authorization codes
	// (32 bytes = 256 bits).
	authCodeBytes = 32
)

// generateID produces a cryptographically random hex-encoded identifier,
// mirroring session.generateSessionID.
func generateID(nBytes int) (string, error) {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// splitScope splits a space-delimited OAuth2 scope string into individual
// scopes, per RFC 6749 §3.3.
func splitScope(scope string) []string {
	if strings.TrimSpace(scope) == "" {
		return nil
	}
	return strings.Fields(scope)
}

// joinScopes joins scopes back into a space-delimited string.
func joinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// containsScope reports whether scopes contains the target scope.
func containsScope(scopes []string, target string) bool {
	for _, s := range scopes {
		if s == target {
			return true
		}
	}
	return false
}

// exactRedirectURIMatch reports whether uri exactly matches one of the
// client's registered redirect URIs. Per RFC 6749 §3.1.2.3, redirect URI
// comparison must be exact (no partial/prefix matching).
func exactRedirectURIMatch(registered []string, uri string) bool {
	for _, r := range registered {
		if r == uri {
			return true
		}
	}
	return false
}

// buildRedirectError constructs an OAuth2 error redirect URL per RFC 6749
// §4.1.2.1. Used once redirect_uri has already been validated against the
// client's registration, so further errors are reported to the client via
// redirect rather than a JSON error page.
func buildRedirectError(redirectURI, errCode, errDescription, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("error", errCode)
	if errDescription != "" {
		q.Set("error_description", errDescription)
	}
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// buildRedirectCode constructs the success redirect URL carrying the
// authorization code per RFC 6749 §4.1.2.
func buildRedirectCode(redirectURI, code, state string) string {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return redirectURI
	}
	q := u.Query()
	q.Set("code", code)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// appendQueryParam appends a single query parameter to baseURL, preserving
// any existing query parameters. Used to append login_challenge/
// consent_challenge to the configured login/consent UI base URLs.
func appendQueryParam(baseURL, key, value string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", fmt.Errorf("parse URL: %w", err)
	}
	q := u.Query()
	q.Set(key, value)
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// buildRequestURL reconstructs the original GET /oauth/authorize request URL
// from a stored LoginRequest, for display by the external login UI
// (LoginRequestInfo.RequestURL). The LoginRequest type has no RequestURL
// field of its own (see GH-467 types.go); it is derived on demand here
// instead of duplicating the data in Redis.
func buildRequestURL(lr *LoginRequest) string {
	q := url.Values{}
	q.Set("client_id", lr.ClientID)
	q.Set("redirect_uri", lr.RedirectURI)
	q.Set("response_type", "code")
	q.Set("scope", joinScopes(lr.Scopes))
	if lr.State != "" {
		q.Set("state", lr.State)
	}
	if lr.Nonce != "" {
		q.Set("nonce", lr.Nonce)
	}
	if lr.CodeChallenge != "" {
		q.Set("code_challenge", lr.CodeChallenge)
		q.Set("code_challenge_method", lr.CodeChallengeMethod)
	}
	return RouteAuthorize + "?" + q.Encode()
}
