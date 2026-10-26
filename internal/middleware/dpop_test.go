package middleware_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockDPoPValidator implements middleware.DPoPProofValidator for testing.
// When expectedHTU is set, ValidateProof fails unless the httpURI it receives
// matches exactly — this stands in for the real validator's htu matching
// (RFC 9449 §4.3) without pulling in internal/dpop. gotHTU records the last
// httpURI seen so tests can assert on the reconstructed request URI directly.
type mockDPoPValidator struct {
	enabled     bool
	thumbprint  string
	err         error
	expectedHTU string
	gotHTU      string
}

func (m *mockDPoPValidator) Enabled() bool { return m.enabled }
func (m *mockDPoPValidator) ValidateProof(_ context.Context, _, _, httpURI string) (string, error) {
	m.gotHTU = httpURI
	if m.expectedHTU != "" && httpURI != m.expectedHTU {
		return "", fmt.Errorf("htu %q does not match %q", m.expectedHTU, httpURI)
	}
	if m.err != nil {
		return "", m.err
	}
	return m.thumbprint, nil
}

func newDPoPTestRouter(
	validator middleware.TokenValidator,
	dpopValidator middleware.DPoPProofValidator,
	trustedProxyCIDRs []*net.IPNet,
) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuthMiddleware(validator))
	r.Use(middleware.DPoPMiddleware(dpopValidator, trustedProxyCIDRs))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestDPoPMiddleware_NonBoundToken_NoProofRequired(t *testing.T) {
	// Token has no JKTThumbprint — should pass without DPoP header.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject: "user-1",
			TokenID: "tok-1",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "test-jkt"}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_BoundToken_ValidProof(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "matching-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:    true,
		thumbprint: "matching-jkt",
	}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "valid-proof-jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_BoundToken_MissingProof(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	// No DPoP header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "DPoP proof required")
}

func TestDPoPMiddleware_BoundToken_ThumbprintMismatch(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "expected-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:    true,
		thumbprint: "different-jkt",
	}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "proof-jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "does not match")
}

func TestDPoPMiddleware_BoundToken_InvalidProof(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled: true,
		err:     fmt.Errorf("signature verification failed"),
	}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "invalid-proof")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

func TestDPoPMiddleware_BoundToken_DPoPDisabled(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: false}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "some-proof")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "not enabled")
}

// --- TRUSTED_PROXY_CIDRS / X-Forwarded-Proto behind a TLS-terminating ALB (GH-508) ---

func TestDPoPMiddleware_TrustedProxy_HonorsForwardedProto(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "jkt-1",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:     true,
		thumbprint:  "jkt-1",
		expectedHTU: "https://auth.quantflow.studio/protected",
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPTestRouter(tokenValidator, dpopValidator, []*net.IPNet{trustedCIDR})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "10.1.2.3:5555" // inside the trusted (ALB/VPC) CIDR
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "valid-proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://auth.quantflow.studio/protected", dpopValidator.gotHTU)
}

func TestDPoPMiddleware_UntrustedProxy_IgnoresForwardedProto(t *testing.T) {
	// Spoofing test: X-Forwarded-Proto from an untrusted source must not flip
	// the reconstructed scheme. The proof below claims an https htu, but since
	// the peer is not in trustedProxyCIDRs the header is ignored, the
	// connection is treated as plain http, and validation fails (htu mismatch).
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "jkt-1",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:     true,
		thumbprint:  "jkt-1",
		expectedHTU: "https://auth.quantflow.studio/protected",
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPTestRouter(tokenValidator, dpopValidator, []*net.IPNet{trustedCIDR})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "203.0.113.9:4444" // outside the trusted CIDR
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "spoofed-proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https") // spoofed; must be ignored
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
	assert.Equal(t, "http://auth.quantflow.studio/protected", dpopValidator.gotHTU)
}

func TestDPoPMiddleware_UntrustedProxy_HTTPHTUStillAccepted(t *testing.T) {
	// Same untrusted peer, but the proof correctly claims http (matching the
	// unforwarded reconstruction) — this must still pass.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "jkt-1",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:     true,
		thumbprint:  "jkt-1",
		expectedHTU: "http://auth.quantflow.studio/protected",
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPTestRouter(tokenValidator, dpopValidator, []*net.IPNet{trustedCIDR})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "203.0.113.9:4444" // outside the trusted CIDR
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "valid-proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https") // spoofed; must be ignored
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://auth.quantflow.studio/protected", dpopValidator.gotHTU)
}

func TestDPoPMiddleware_NoTrustedProxiesConfigured_ForwardedHeadersIgnored(t *testing.T) {
	// Default (TRUSTED_PROXY_CIDRS empty): X-Forwarded-Proto is ignored no
	// matter the peer address, preserving pre-existing behavior.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "jkt-1",
		},
	}
	dpopValidator := &mockDPoPValidator{
		enabled:     true,
		thumbprint:  "jkt-1",
		expectedHTU: "http://auth.quantflow.studio/protected",
	}

	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "10.1.2.3:5555" // would be trusted if any CIDR were configured
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "valid-proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://auth.quantflow.studio/protected", dpopValidator.gotHTU)
}

// --- Host source for htu reconstruction ---

func TestDPoPMiddleware_RequestURI_HostFromRequestHost(t *testing.T) {
	_, albCIDR, err := net.ParseCIDR("10.40.0.0/24")
	require.NoError(t, err)

	tests := []struct {
		name       string
		cidrs      []*net.IPNet
		remoteAddr string
		headers    map[string]string
		wantHTU    string
	}{
		{
			name:       "trusted peer: X-Forwarded-Host is ignored, X-Forwarded-Proto honored",
			cidrs:      []*net.IPNet{albCIDR},
			remoteAddr: "10.40.0.5:5555",
			headers: map[string]string{
				"X-Forwarded-Host":  "evil.example",
				"X-Forwarded-Proto": "https",
			},
			wantHTU: "https://auth.quantflow.studio/protected",
		},
		{
			name:       "trusted peer: X-Forwarded-Host alone does not change host",
			cidrs:      []*net.IPNet{albCIDR},
			remoteAddr: "10.40.0.5:5555",
			headers:    map[string]string{"X-Forwarded-Host": "evil.example"},
			wantHTU:    "http://auth.quantflow.studio/protected",
		},
		{
			name:       "untrusted peer: both forwarded headers ignored",
			cidrs:      []*net.IPNet{albCIDR},
			remoteAddr: "203.0.113.9:4444",
			headers: map[string]string{
				"X-Forwarded-Host":  "evil.example",
				"X-Forwarded-Proto": "https",
			},
			wantHTU: "http://auth.quantflow.studio/protected",
		},
		{
			name:       "no CIDRs configured: both forwarded headers ignored",
			cidrs:      nil,
			remoteAddr: "10.40.0.5:5555",
			headers: map[string]string{
				"X-Forwarded-Host":  "evil.example",
				"X-Forwarded-Proto": "https",
			},
			wantHTU: "http://auth.quantflow.studio/protected",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokenValidator := &mockValidator{
				claims: &domain.TokenClaims{
					Subject:       "user-1",
					TokenID:       "tok-1",
					JKTThumbprint: "jkt-1",
				},
			}
			dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "jkt-1"}
			router := newDPoPTestRouter(tokenValidator, dpopValidator, tt.cidrs)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			req.Host = "auth.quantflow.studio"
			req.RemoteAddr = tt.remoteAddr
			req.Header.Set("Authorization", "Bearer qf_at_valid")
			req.Header.Set("DPoP", "proof")
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tt.wantHTU, dpopValidator.gotHTU)
		})
	}
}
