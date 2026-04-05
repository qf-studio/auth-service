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

type mockDPoPService struct {
	enabled    bool
	thumbprint string
	err        error
}

func (m *mockDPoPService) Enabled() bool { return m.enabled }
func (m *mockDPoPService) ValidateProof(_ context.Context, _, _, _ string) (*api.DPoPProofClaims, error) {
	if m.err != nil {
		return nil, m.err
	}
	return &api.DPoPProofClaims{JKTThumbprint: m.thumbprint}, nil
}
func (m *mockDPoPService) IssueNonce(_ context.Context) (string, error) {
	return "test-nonce", nil
}

// mockDPoPProofValidator for middleware testing.
type mockDPoPMWValidator struct {
	enabled    bool
	thumbprint string
	err        error
}

func (m *mockDPoPMWValidator) Enabled() bool { return m.enabled }
func (m *mockDPoPMWValidator) ValidateProof(_ context.Context, _, _, _ string) (string, error) {
	return m.thumbprint, m.err
}

// newDPoPIntegrationRouter builds a full public router with DPoP support.
func newDPoPIntegrationRouter(
	authSvc api.AuthService,
	tokenSvc api.TokenService,
	dpopSvc api.DPoPService,
	validator middleware.TokenValidator,
	dpopValidator middleware.DPoPProofValidator,
) *gin.Engine {
	svc := &api.Services{Auth: authSvc, Token: tokenSvc, DPoP: dpopSvc}
	mw := &api.MiddlewareStack{
		Auth: middleware.AuthMiddleware(validator),
	}
	if dpopValidator != nil {
		mw.DPoP = middleware.DPoPMiddleware(dpopValidator)
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

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, dpopSvc, validator, nil)

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

	router := newDPoPIntegrationRouter(&mockAuthService{}, tokenSvc, nil, validator, nil)

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

func TestDPoP_TokenEndpoint_InvalidProof(t *testing.T) {
	dpopSvc := &mockDPoPService{
		enabled: true,
		err:     fmt.Errorf("invalid signature"),
	}

	validator := &mockTokenValidator{
		claims: &domain.TokenClaims{Subject: "user-1", TokenID: "tok-1"},
	}

	router := newDPoPIntegrationRouter(&mockAuthService{}, &mockTokenService{}, dpopSvc, validator, nil)

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
	)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/auth/me", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_bearer_token")
	// No DPoP header — should work fine for unbound tokens
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}
