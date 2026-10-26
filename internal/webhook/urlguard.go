package webhook

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strings"
	"syscall"
)

// ErrBlockedAddress is returned when a webhook target resolves to, or is, an
// address in a non-public range.
var ErrBlockedAddress = errors.New("webhook target address is not a public address")

// blockedPrefixes lists ranges that are not valid webhook destinations on top
// of what netip's IsLoopback/IsPrivate/IsLinkLocal* helpers already cover.
var blockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),     // "this" network (RFC 1122)
	netip.MustParsePrefix("100.64.0.0/10"), // CGNAT (RFC 6598)
	netip.MustParsePrefix("192.0.0.0/24"),  // IETF protocol assignments (RFC 6890)
	netip.MustParsePrefix("198.18.0.0/15"), // benchmarking (RFC 2544)
	netip.MustParsePrefix("240.0.0.0/4"),   // reserved (RFC 1112)
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64 (RFC 6052)
	netip.MustParsePrefix("100::/64"),      // discard-only (RFC 6666)
	netip.MustParsePrefix("2001:db8::/32"), // documentation (RFC 3849)
}

// IsBlockedIP reports whether ip is loopback, private (RFC 1918), link-local
// (including 169.254.0.0/16 cloud metadata), CGNAT, unique-local IPv6,
// multicast, unspecified or otherwise reserved. IPv4-mapped IPv6 addresses are
// unmapped first so ::ffff:127.0.0.1 cannot bypass the filter.
func IsBlockedIP(ip netip.Addr) bool {
	ip = ip.Unmap().WithZone("")
	if !ip.IsValid() {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// ValidateTargetURL checks that raw is an absolute https URL whose host is not
// localhost or an IP literal in a non-public range. Hostnames are not
// resolved here; the dispatcher re-checks the resolved address at dial time.
func ValidateTargetURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid url: %w", err)
	}
	if u.Scheme != "https" {
		return errors.New("url scheme must be https")
	}
	if u.User != nil {
		return errors.New("url must not contain credentials")
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return errors.New("url host is required")
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return fmt.Errorf("%w: localhost", ErrBlockedAddress)
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		if IsBlockedIP(ip) {
			return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
		}
	}
	return nil
}

// controlPublicOnly is a net.Dialer Control func. It runs after DNS resolution
// with the concrete address about to be connected to, which makes the check
// immune to DNS rebinding.
func controlPublicOnly(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlockedAddress, err)
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBlockedAddress, err)
	}
	if IsBlockedIP(ip) {
		return fmt.Errorf("%w: %s", ErrBlockedAddress, ip)
	}
	return nil
}
