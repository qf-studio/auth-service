package api_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// --- DPoP test helpers ---

func generateECKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key
}

func ecPublicJWK(pub *ecdsa.PublicKey) map[string]interface{} {
	byteLen := (pub.Curve.Params().BitSize + 7) / 8
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()
	xPadded := make([]byte, byteLen)
	yPadded := make([]byte, byteLen)
	copy(xPadded[byteLen-len(xBytes):], xBytes)
	copy(yPadded[byteLen-len(yBytes):], yBytes)
	return map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(xPadded),
		"y":   base64.RawURLEncoding.EncodeToString(yPadded),
	}
}

func computeThumbprint(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	jwk := ecPublicJWK(pub)
	canonical := map[string]interface{}{
		"crv": jwk["crv"],
		"kty": jwk["kty"],
		"x":   jwk["x"],
		"y":   jwk["y"],
	}
	b, err := json.Marshal(canonical)
	require.NoError(t, err)
	hash := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func buildDPoPProof(t *testing.T, key *ecdsa.PrivateKey, method, uri, jti string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"jti": jti,
		"htm": method,
		"htu": uri,
		"iat": float64(time.Now().Unix()),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["typ"] = "dpop+jwt"
	token.Header["jwk"] = ecPublicJWK(&key.PublicKey)
	signed, err := token.SignedString(key)
	require.NoError(t, err)
	return signed
}

// --- Mock DPoP service ---

// mockDPoPService implements api.DPoPService for testing. When expectedHTU is
// set, ValidateProof fails unless the httpURI it receives matches exactly —
// this stands in for the real service's htu matching (RFC 9449 §4.3)
// without pulling in internal/dpop. gotHTU records the last httpURI seen so
// tests can assert on the reconstructed request URI directly.
type mockDPoPService struct {
	enabled     bool
	thumbprint  string
	err         error
	expectedHTU string
	gotHTU      string
}

func (m *mockDPoPService) Enabled() bool { return m.enabled }
func (m *mockDPoPService) ValidateProof(_ context.Context, _, _, httpURI string) (*api.DPoPProofClaims, error) {
	m.gotHTU = httpURI
	if m.expectedHTU != "" && httpURI != m.expectedHTU {
		return nil, fmt.Errorf("htu %q does not match %q", m.expectedHTU, httpURI)
	}
	if m.err != nil {
		return nil, m.err
	}
	return &api.DPoPProofClaims{JKTThumbprint: m.thumbprint}, nil
}
func (m *mockDPoPService) IssueNonce(_ context.Context) (string, error) {
	return "test-nonce", nil
}

// mockDPoPMWValidator implements middleware.DPoPProofValidator for testing,
// with the same expectedHTU/gotHTU behavior as mockDPoPService above.
type mockDPoPMWValidator struct {
	enabled     bool
	thumbprint  string
	err         error
	expectedHTU string
	gotHTU      string
}

func (m *mockDPoPMWValidator) Enabled() bool { return m.enabled }
func (m *mockDPoPMWValidator) ValidateProof(_ context.Context, _, _, httpURI string) (string, error) {
	m.gotHTU = httpURI
	if m.expectedHTU != "" && httpURI != m.expectedHTU {
		return "", fmt.Errorf("htu %q does not match %q", m.expectedHTU, httpURI)
	}
	if m.err != nil {
		return "", m.err
	}
	return m.thumbprint, nil
}

// newDPoPIntegrationRouter builds a full public router with DPoP support.
// trustedProxyCIDRs controls when X-Forwarded-Proto / X-Forwarded-Host are
// honored while reconstructing the request URI for htu matching.
func newDPoPIntegrationRouter(
	authSvc api.AuthService,
	tokenSvc api.TokenService,
	dpopSvc api.DPoPService,
	validator middleware.TokenValidator,
	dpopValidator middleware.DPoPProofValidator,
	trustedProxyCIDRs []*net.IPNet,
) *gin.Engine {
	svc := &api.Services{Auth: authSvc, Token: tokenSvc, DPoP: dpopSvc, TrustedProxyCIDRs: trustedProxyCIDRs}
	mw := &api.MiddlewareStack{
		Auth: middleware.AuthMiddleware(validator),
	}
	if dpopValidator != nil {
		mw.DPoP = middleware.DPoPMiddleware(dpopValidator, trustedProxyCIDRs)
	}
	return api.NewPublicRouter(svc, mw, health.NewService())
}

// --- Integration Tests ---

func TestDPoP_TokenEndpoint_WithDPoPProof(t *testing.T) {
	key := generateECKey(t)
	thumbprint := computeThumbprint(t, &key.PublicKey)

	dpopSvc := &mockDPoPService{
		enabled:    true,
		thumbprint: thumbprint,
	}

	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_dpop_bound",
				RefreshToken: "qf_rt_new",
				TokenType:    "DPoP",
				ExpiresIn:    900,
			}, nil
		},
	}

	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, dpopSvc, validator, nil, nil)

	proof := buildDPoPProof(t, key, "POST", "http://localhost/auth/token", "jti-integ-1")

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", proof)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "DPoP", resp.TokenType)
}

func TestDPoP_TokenEndpoint_WithoutDPoP_ReturnsBearer(t *testing.T) {
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken:  "qf_at_bearer",
				RefreshToken: "qf_rt_new",
				TokenType:    "Bearer",
				ExpiresIn:    900,
			}, nil
		},
	}

	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, nil, validator, nil, nil)

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AuthResult
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "Bearer", resp.TokenType)
}

// --- TRUSTED_PROXY_CIDRS / X-Forwarded-Proto behind a TLS-terminating ALB (GH-508) ---
// Exercises internal/api/token_handlers.go's requestURI reconstruction, the
// second of the two htu-scheme sites fixed for GH-508 (the first being
// internal/middleware/dpop.go, covered by internal/middleware/dpop_test.go).

func TestDPoP_TokenEndpoint_TrustedProxy_HonorsForwardedProto(t *testing.T) {
	dpopSvc := &mockDPoPService{
		enabled:     true,
		thumbprint:  "jkt-trusted",
		expectedHTU: "https://auth.quantflow.studio/auth/token",
	}
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken: "qf_at_x",
				TokenType:   "DPoP",
				ExpiresIn:   900,
			}, nil
		},
	}
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, dpopSvc, validator, nil, []*net.IPNet{trustedCIDR})

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "10.5.5.5:9999" // inside the trusted (ALB/VPC) CIDR
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "proof")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "https://auth.quantflow.studio/auth/token", dpopSvc.gotHTU)
}

func TestDPoP_TokenEndpoint_UntrustedProxy_ForwardedProtoIgnored(t *testing.T) {
	// Spoofing test: X-Forwarded-Proto from an untrusted source must not flip
	// the reconstructed scheme. The proof below claims an https htu, but since
	// the peer is not in the trusted CIDRs the header is ignored, the
	// connection is treated as plain http, and validation fails.
	dpopSvc := &mockDPoPService{
		enabled:     true,
		expectedHTU: "https://auth.quantflow.studio/auth/token",
	}
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPIntegrationRouter(&mockAuthService{}, &mockTokenService{}, dpopSvc, validator, nil, []*net.IPNet{trustedCIDR})

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "203.0.113.9:1111" // outside the trusted CIDR
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "spoofed-proof")
	req.Header.Set("X-Forwarded-Proto", "https") // spoofed; must be ignored
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
	assert.Equal(t, "http://auth.quantflow.studio/auth/token", dpopSvc.gotHTU)
}

func TestDPoP_TokenEndpoint_UntrustedProxy_HTTPHTUStillAccepted(t *testing.T) {
	dpopSvc := &mockDPoPService{
		enabled:     true,
		thumbprint:  "jkt-untrusted",
		expectedHTU: "http://auth.quantflow.studio/auth/token",
	}
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken: "qf_at_y",
				TokenType:   "DPoP",
				ExpiresIn:   900,
			}, nil
		},
	}
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	_, trustedCIDR, err := net.ParseCIDR("10.0.0.0/8")
	require.NoError(t, err)

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, dpopSvc, validator, nil, []*net.IPNet{trustedCIDR})

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "203.0.113.9:1111" // outside the trusted CIDR
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "proof")
	req.Header.Set("X-Forwarded-Proto", "https") // spoofed; must be ignored
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://auth.quantflow.studio/auth/token", dpopSvc.gotHTU)
}

func TestDPoP_TokenEndpoint_NoTrustedProxiesConfigured_ForwardedHeaderIgnored(t *testing.T) {
	// Default (TRUSTED_PROXY_CIDRS empty): X-Forwarded-Proto is ignored no
	// matter the peer address, preserving pre-existing behavior.
	dpopSvc := &mockDPoPService{
		enabled:     true,
		thumbprint:  "jkt-default",
		expectedHTU: "http://auth.quantflow.studio/auth/token",
	}
	tokenSvc := &mockTokenService{
		refreshFn: func(_ context.Context, _ string) (*api.AuthResult, error) {
			return &api.AuthResult{
				AccessToken: "qf_at_z",
				TokenType:   "DPoP",
				ExpiresIn:   900,
			}, nil
		},
	}
	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, dpopSvc, validator, nil, nil)

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Host = "auth.quantflow.studio"
	req.RemoteAddr = "10.5.5.5:9999" // would be trusted if any CIDR were configured
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "proof")
	req.Header.Set("X-Forwarded-Proto", "https")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "http://auth.quantflow.studio/auth/token", dpopSvc.gotHTU)
}

func TestDPoP_TokenEndpoint_InvalidProof(t *testing.T) {
	dpopSvc := &mockDPoPService{
		enabled: true,
		err:     fmt.Errorf("invalid signature"),
	}

	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	router := newDPoPIntegrationRouter(&mockAuthService{}, &mockTokenService{}, dpopSvc, validator, nil, nil)

	body := `{"grant_type":"refresh_token","refresh_token":"qf_rt_valid"}`
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("DPoP", "invalid-proof")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

func TestDPoP_ProtectedEndpoint_BoundToken_ValidProof(t *testing.T) {
	key := generateECKey(t)
	thumbprint := computeThumbprint(t, &key.PublicKey)

	tokenValidator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-dpop",
			TokenID:       "tok-dpop",
			JKTThumbprint: thumbprint,
		},
	}

	dpopMWValidator := &mockDPoPMWValidator{
		enabled:    true,
		thumbprint: thumbprint,
	}

	router := newDPoPIntegrationRouter(
		&mockAuthService{},
		&mockTokenService{},
		nil,
		tokenValidator,
		dpopMWValidator,
		nil,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_dpop_bound_token")
	req.Header.Set("DPoP", "valid-dpop-proof")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoP_ProtectedEndpoint_BoundToken_MissingProof(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-dpop",
			TokenID:       "tok-dpop",
			JKTThumbprint: "some-jkt",
		},
	}

	dpopMWValidator := &mockDPoPMWValidator{
		enabled:    true,
		thumbprint: "some-jkt",
	}

	router := newDPoPIntegrationRouter(
		&mockAuthService{},
		&mockTokenService{},
		nil,
		tokenValidator,
		dpopMWValidator,
		nil,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_dpop_bound_token")
	// No DPoP header
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "DPoP proof required")
}

func TestDPoP_ProtectedEndpoint_BoundToken_WrongKey(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject:       "user-dpop",
			TokenID:       "tok-dpop",
			JKTThumbprint: "expected-jkt",
		},
	}

	dpopMWValidator := &mockDPoPMWValidator{
		enabled:    true,
		thumbprint: "wrong-jkt",
	}

	router := newDPoPIntegrationRouter(
		&mockAuthService{},
		&mockTokenService{},
		nil,
		tokenValidator,
		dpopMWValidator,
		nil,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_dpop_bound_token")
	req.Header.Set("DPoP", "proof-with-different-key")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "does not match")
}

func TestDPoP_ProtectedEndpoint_UnboundToken_NoProofNeeded(t *testing.T) {
	tokenValidator := &mockTokenValidator{
		claims: &domain.TokenClaims{
			Subject: "user-bearer",
			TokenID: "tok-bearer",
			// No JKTThumbprint — unbound token
		},
	}

	dpopMWValidator := &mockDPoPMWValidator{
		enabled:    true,
		thumbprint: "irrelevant",
	}

	router := newDPoPIntegrationRouter(
		&mockAuthService{},
		&mockTokenService{},
		nil,
		tokenValidator,
		dpopMWValidator,
		nil,
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_bearer_token")
	// No DPoP header — should work fine for unbound tokens
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
