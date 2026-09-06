package middleware

import (
	"fmt"
	"net"
	"net/http"
	"strings"
)

// TrustedProxies is a set of CIDR ranges whose X-Forwarded-Proto and
// X-Forwarded-Host headers are trusted when reconstructing the
// externally-visible scheme/host for a request (GH-508).
//
// Behind a TLS-terminating reverse proxy (e.g. an AWS ALB), the backend
// only ever sees plaintext HTTP, so Request.TLS is always nil — scheme
// detection cannot rely on it alone without misclassifying every request
// as http.
//
// A nil/empty set trusts nothing, which reproduces the pre-GH-508
// behaviour of deriving scheme solely from Request.TLS and host solely
// from Request.Host.
type TrustedProxies []*net.IPNet

// ParseTrustedProxyCIDRs parses TRUSTED_PROXY_CIDRS-style CIDR strings
// (already comma-split by the config loader) into a TrustedProxies set.
func ParseTrustedProxyCIDRs(cidrs []string) (TrustedProxies, error) {
	if len(cidrs) == 0 {
		return nil, nil
	}
	out := make(TrustedProxies, 0, len(cidrs))
	for _, raw := range cidrs {
		_, ipNet, err := net.ParseCIDR(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", raw, err)
		}
		out = append(out, ipNet)
	}
	return out, nil
}

// contains reports whether remoteAddr (as found on http.Request.RemoteAddr —
// "host:port", or a bare host) falls within any trusted CIDR range. An
// empty set never matches, regardless of remoteAddr.
func (t TrustedProxies) contains(remoteAddr string) bool {
	if len(t) == 0 {
		return false
	}
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}
	for _, ipNet := range t {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// PublicSchemeHost derives the externally-visible scheme and host for r.
// It only trusts the X-Forwarded-Proto / X-Forwarded-Host headers when r
// arrived from an address within trustedProxies; otherwise (including when
// trustedProxies is empty) it falls back to r.TLS / r.Host — the original
// pre-GH-508 behaviour. This is what prevents an untrusted client from
// spoofing the scheme by simply sending its own X-Forwarded-Proto header.
func PublicSchemeHost(r *http.Request, trustedProxies TrustedProxies) (scheme, host string) {
	scheme = "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host = r.Host

	if !trustedProxies.contains(r.RemoteAddr) {
		return scheme, host
	}

	if fwdProto := firstForwardedValue(r.Header.Get("X-Forwarded-Proto")); fwdProto != "" {
		scheme = strings.ToLower(fwdProto)
	}
	if fwdHost := firstForwardedValue(r.Header.Get("X-Forwarded-Host")); fwdHost != "" {
		host = fwdHost
	}
	return scheme, host
}

// firstForwardedValue returns the left-most comma-separated value in an
// X-Forwarded-* header (the value nearest the original client), trimmed of
// surrounding whitespace. Returns "" for an empty header.
func firstForwardedValue(header string) string {
	if header == "" {
		return ""
	}
	return strings.TrimSpace(strings.Split(header, ",")[0])
}
