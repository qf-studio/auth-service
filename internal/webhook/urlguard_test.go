package webhook

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateTargetURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		{"public https host", "https://example.com", false},
		{"public https with path and port", "https://example.com:8443/hooks/a?x=1", false},
		{"public IPv4 literal", "https://93.184.216.34/hook", false},
		{"http scheme", "http://example.com", true},
		{"ftp scheme", "ftp://example.com", true},
		{"no scheme", "example.com/hook", true},
		{"empty", "", true},
		{"no host", "https:///path", true},
		{"loopback v4", "https://127.0.0.1", true},
		{"loopback v4 other", "https://127.1.2.3:8443", true},
		{"metadata link-local", "https://169.254.169.254/latest/meta-data", true},
		{"rfc1918 10/8", "https://10.0.0.1", true},
		{"rfc1918 172.16/12", "https://172.16.5.4", true},
		{"rfc1918 192.168/16", "https://192.168.1.1", true},
		{"cgnat", "https://100.64.0.1", true},
		{"cgnat upper edge", "https://100.127.255.254", true},
		{"unspecified", "https://0.0.0.0", true},
		{"loopback v6", "https://[::1]", true},
		{"loopback v6 port", "https://[::1]:8443/x", true},
		{"unique local v6", "https://[fd00::1]", true},
		{"link-local v6", "https://[fe80::1]", true},
		{"v4-mapped loopback", "https://[::ffff:127.0.0.1]", true},
		{"v4-mapped metadata", "https://[::ffff:169.254.169.254]", true},
		{"localhost", "https://localhost", true},
		{"localhost mixed case", "https://LocalHost:8443", true},
		{"localhost trailing dot", "https://localhost./", true},
		{"localhost subdomain", "https://api.localhost", true},
		{"embedded credentials", "https://user:pass@example.com", true},
		{"credentials hiding loopback", "https://example.com@127.0.0.1", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTargetURL(tt.url)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIsBlockedIP(t *testing.T) {
	tests := []struct {
		ip      string
		blocked bool
	}{
		{"93.184.216.34", false},
		{"8.8.8.8", false},
		{"100.63.255.255", false},
		{"100.128.0.0", false},
		{"2606:2800:220:1:248:1893:25c8:1946", false},
		{"127.0.0.1", true},
		{"10.1.2.3", true},
		{"172.31.255.255", true},
		{"192.168.0.1", true},
		{"169.254.169.254", true},
		{"100.64.0.0", true},
		{"0.0.0.0", true},
		{"224.0.0.1", true},
		{"255.255.255.255", true},
		{"::", true},
		{"::1", true},
		{"fc00::1", true},
		{"fd12:3456::1", true},
		{"fe80::1", true},
		{"ff02::1", true},
		{"::ffff:10.0.0.1", true},
		{"64:ff9b::7f00:1", true},
	}
	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			assert.Equal(t, tt.blocked, IsBlockedIP(netip.MustParseAddr(tt.ip)))
		})
	}
}
