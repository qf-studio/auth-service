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

// mockDPoPVerifier implements middleware.DPoPVerifier for testing.
type mockDPoPVerifier struct {
	enabled     bool
	thumbprint  string
	validateErr error
}

func (m *mockDPoPVerifier) Enabled() bool {
	return m.enabled
}

func (m *mockDPoPVerifier) ValidateProof(_ context.Context, _, _, _ string) (*middleware.DPoPProofResult, error) {
	if m.validateErr != nil {
		return nil, m.validateErr
	}
	return &middleware.DPoPProofResult{JWKThumbprint: m.thumbprint}, nil
}

func requestURIFn(c *gin.Context) string {
	return "https://auth.example.com" + c.Request.URL.Path
}

func newDPoPTestRouter(claims *domain.TokenClaims, verifier middleware.DPoPVerifier) *gin.Engine {
	r := gin.New()

	// Simulate AuthMiddleware by injecting claims.
	r.Use(func(c *gin.Context) {
		if claims != nil {
			c.Set("claims", claims)
			c.Set("user_id", claims.Subject)
		}
		c.Next()
	})

	r.Use(middleware.DPoPMiddleware(verifier, requestURIFn))
	r.GET("/protected", func(c *gin.Context) {
		thumbprint := middleware.GetDPoPThumbprint(c)
		c.String(http.StatusOK, thumbprint)
	})
	return r
}

func TestDPoPMiddleware_Disabled(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "some-thumbprint",
	}
	verifier := &mockDPoPVerifier{enabled: false}
	router := newDPoPTestRouter(claims, verifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_NoClaims_PassThrough(t *testing.T) {
	verifier := &mockDPoPVerifier{enabled: true}
	router := newDPoPTestRouter(nil, verifier) // No claims = not authenticated.

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_NoBound_PassThrough(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "", // Not DPoP-bound.
	}
	verifier := &mockDPoPVerifier{enabled: true}
	router := newDPoPTestRouter(claims, verifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestDPoPMiddleware_BoundToken_ProofRequired(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "expected-thumbprint",
	}
	verifier := &mockDPoPVerifier{enabled: true, thumbprint: "expected-thumbprint"}
	router := newDPoPTestRouter(claims, verifier)

	// No DPoP header → should fail.
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "DPoP proof required")
}

func TestDPoPMiddleware_BoundToken_ValidProof(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "expected-thumbprint",
	}
	verifier := &mockDPoPVerifier{enabled: true, thumbprint: "expected-thumbprint"}
	router := newDPoPTestRouter(claims, verifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("DPoP", "valid-proof-jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "expected-thumbprint", w.Body.String())
}

func TestDPoPMiddleware_BoundToken_ThumbprintMismatch(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "expected-thumbprint",
	}
	verifier := &mockDPoPVerifier{enabled: true, thumbprint: "different-thumbprint"}
	router := newDPoPTestRouter(claims, verifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("DPoP", "some-proof-jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "does not match")
}

func TestDPoPMiddleware_BoundToken_InvalidProof(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:       "user-123",
		JWKThumbprint: "expected-thumbprint",
	}
	verifier := &mockDPoPVerifier{enabled: true, validateErr: fmt.Errorf("invalid signature")}
	router := newDPoPTestRouter(claims, verifier)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("DPoP", "bad-proof-jwt")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "invalid DPoP proof")
}

func TestGetDPoPThumbprint_Empty(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	assert.Empty(t, middleware.GetDPoPThumbprint(c))
}

func TestGetDPoPThumbprint_Set(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Set("dpop_thumbprint", "test-thumb")

	result := middleware.GetDPoPThumbprint(c)
	require.Equal(t, "test-thumb", result)
}
