package middleware_test

import (
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/middleware"
)

func TestParseTrustedProxyCIDRs_Empty(t *testing.T) {
	tp, err := middleware.ParseTrustedProxyCIDRs(nil)
	require.NoError(t, err)
	assert.Empty(t, tp)
}

func TestParseTrustedProxyCIDRs_Invalid(t *testing.T) {
	_, err := middleware.ParseTrustedProxyCIDRs([]string{"not-a-cidr"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not-a-cidr")
}

func TestPublicSchemeHost_NoTrustedProxies_FallsBackToTLSAndHost(t *testing.T) {
	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spoofed.example.com")
	req.RemoteAddr = "203.0.113.5:1234"

	scheme, host := middleware.PublicSchemeHost(req, nil)

	assert.Equal(t, "http", scheme) // req.TLS is nil in httptest
	assert.Equal(t, "example.com", host)
}

func TestPublicSchemeHost_TrustedProxy_UsesForwardedHeaders(t *testing.T) {
	tp, err := middleware.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "auth.quantflow.studio")
	req.RemoteAddr = "10.1.2.3:5678"

	scheme, host := middleware.PublicSchemeHost(req, tp)

	assert.Equal(t, "https", scheme)
	assert.Equal(t, "auth.quantflow.studio", host)
}

func TestPublicSchemeHost_UntrustedSource_HeadersIgnored(t *testing.T) {
	// Spoofing test: an address outside the trusted CIDRs cannot flip the
	// scheme or host via X-Forwarded-* headers.
	tp, err := middleware.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("X-Forwarded-Host", "spoofed.example.com")
	req.RemoteAddr = "203.0.113.5:1234"

	scheme, host := middleware.PublicSchemeHost(req, tp)

	assert.Equal(t, "http", scheme)
	assert.Equal(t, "example.com", host)
}

func TestPublicSchemeHost_TrustedProxy_NoForwardedHeader_UnchangedBehavior(t *testing.T) {
	tp, err := middleware.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.RemoteAddr = "10.1.2.3:5678"

	scheme, host := middleware.PublicSchemeHost(req, tp)

	assert.Equal(t, "http", scheme)
	assert.Equal(t, "example.com", host)
}

func TestPublicSchemeHost_TrustedProxy_MultipleForwardedValues_UsesFirst(t *testing.T) {
	// Per convention, the left-most value in a comma-separated
	// X-Forwarded-* header is the one nearest the original client.
	tp, err := middleware.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("X-Forwarded-Proto", "https, http")
	req.RemoteAddr = "10.1.2.3:5678"

	scheme, _ := middleware.PublicSchemeHost(req, tp)

	assert.Equal(t, "https", scheme)
}

func TestPublicSchemeHost_RemoteAddrWithoutPort(t *testing.T) {
	tp, err := middleware.ParseTrustedProxyCIDRs([]string{"10.0.0.0/8"})
	require.NoError(t, err)

	req := httptest.NewRequest("GET", "/oauth/token", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "10.1.2.3" // no port

	scheme, _ := middleware.PublicSchemeHost(req, tp)

	assert.Equal(t, "https", scheme)
}
