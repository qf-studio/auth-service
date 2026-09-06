package middleware_test

import (
	"context"
	"fmt"
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
// gotHTTPURI records the httpURI argument DPoPMiddleware passed to
// ValidateProof, so tests can assert on the scheme/host it reconstructed.
type mockDPoPValidator struct {
	enabled    bool
	thumbprint string
	err        error
	gotHTTPURI string
}

func (m *mockDPoPValidator) Enabled() bool { return m.enabled }
func (m *mockDPoPValidator) ValidateProof(_ context.Context, _, _, httpURI string) (string, error) {
	m.gotHTTPURI = httpURI
	return m.thumbprint, m.err
}

func newDPoPTestRouter(
	validator middleware.TokenValidator,
	dpopValidator middleware.DPoPProofValidator,
	trustedProxies middleware.TrustedProxies,
) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuthMiddleware(validator))
	r.Use(middleware.DPoPMiddleware(dpopValidator, trustedProxies))
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

// --- GH-508: htu scheme reconstruction behind a trusted reverse proxy ---

func mustTrustedProxies(t *testing.T, cidrs ...string) middleware.TrustedProxies {
	t.Helper()
	tp, err := middleware.ParseTrustedProxyCIDRs(cidrs)
	require.NoError(t, err)
	return tp
}

func TestDPoPMiddleware_TrustedProxy_ForwardedProtoHTTPS_UsesHTTPSScheme(t *testing.T) {
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "some-jkt"}
	trustedProxies := mustTrustedProxies(t, "10.0.0.0/8")
	router := newDPoPTestRouter(tokenValidator, dpopValidator, trustedProxies)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "10.0.0.5:12345" // inside the trusted CIDR (e.g. the ALB)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://example.com/protected", dpopValidator.gotHTTPURI)
}

func TestDPoPMiddleware_UntrustedProxy_ForwardedProtoIgnored(t *testing.T) {
	// Spoofing test: an untrusted source cannot flip the scheme via
	// X-Forwarded-Proto, even when the header is present.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "some-jkt"}
	trustedProxies := mustTrustedProxies(t, "10.0.0.0/8")
	router := newDPoPTestRouter(tokenValidator, dpopValidator, trustedProxies)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "203.0.113.5:12345" // outside the trusted CIDR
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://example.com/protected", dpopValidator.gotHTTPURI)
}

func TestDPoPMiddleware_NoTrustedProxiesConfigured_HeaderIgnored(t *testing.T) {
	// Default (empty trustedProxies): behaviour is unchanged even if a
	// client sends X-Forwarded-Proto.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "some-jkt"}
	router := newDPoPTestRouter(tokenValidator, dpopValidator, nil)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "proof-jwt")
	req.Header.Set("X-Forwarded-Proto", "https")
	req.RemoteAddr = "203.0.113.5:12345"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://example.com/protected", dpopValidator.gotHTTPURI)
}

func TestDPoPMiddleware_TrustedProxy_NoForwardedHeader_UnchangedBehavior(t *testing.T) {
	// A trusted proxy that doesn't set X-Forwarded-Proto (e.g. not actually
	// proxying) must not change scheme detection.
	tokenValidator := &mockValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-1",
			TokenID:       "tok-1",
			JKTThumbprint: "some-jkt",
		},
	}
	dpopValidator := &mockDPoPValidator{enabled: true, thumbprint: "some-jkt"}
	trustedProxies := mustTrustedProxies(t, "10.0.0.0/8")
	router := newDPoPTestRouter(tokenValidator, dpopValidator, trustedProxies)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "proof-jwt")
	req.RemoteAddr = "10.0.0.5:12345"
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://example.com/protected", dpopValidator.gotHTTPURI)
}
