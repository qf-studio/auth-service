package domain

import "strings"

// refreshTokenPrefix is the leak-detection prefix prepended to refresh
// tokens (mirrors token.refreshTokenPrefix, duplicated here since domain
// must not import the token package).
const refreshTokenPrefix = "qf_rt_"

// RefreshTokenSignature extracts the signature segment from a refresh token
// string of the form "qf_rt_<keyEncoded>.<sigEncoded>". The signature is the
// only part ever persisted to the refresh_tokens table (never the full
// token) — this helper centralizes that parse so the login-time store
// (internal/auth/service.go) and introspection lookup
// (internal/admin/token_service.go) can't drift apart (GH-486).
//
// Returns ok=false if the token doesn't carry the qf_rt_ prefix, has no "."
// separator, or the signature segment is empty.
func RefreshTokenSignature(token string) (string, bool) {
	if !strings.HasPrefix(token, refreshTokenPrefix) {
		return "", false
	}

	raw := strings.TrimPrefix(token, refreshTokenPrefix)
	parts := strings.SplitN(raw, ".", 2)
	if len(parts) != 2 || parts[1] == "" {
		return "", false
	}

	return parts[1], true
}
