package middleware_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockDPoPValidator implements middleware.DPoPProofValidator for testing.
type mockDPoPValidator struct {
	enabled    bool
	thumbprint string
	err        error
}

func (m *mockDPoPValidator) Enabled() bool { return m.enabled }
func (m *mockDPoPValidator) ValidateProof(_ context.Context, _, _, _ string) (string, error) {
	return m.thumbprint, m.err
}

func newDPoPTestRouter(
	validator middleware.TokenValidator,
	dpopValidator middleware.DPoPProofValidator,
) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuthMiddleware(validator))
	r.Use(middleware.DPoPMiddleware(dpopValidator))
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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

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
	router := newDPoPTestRouter(tokenValidator, dpopValidator)

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_valid")
	req.Header.Set("DPoP", "some-proof")
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "not enabled")
}
