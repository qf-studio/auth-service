package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockDPoPVerifier implements middleware.DPoPVerifier for testing.
type mockDPoPVerifier struct {
	thumbprint string
	err        error
}

func (m *mockDPoPVerifier) VerifyProof(_ context.Context, _, _, _ string) (string, error) {
	return m.thumbprint, m.err
}

// newDPoPTestRouter builds a router with AuthMiddleware (using a mock validator
// that injects the given claims) followed by DPoPMiddleware.
func newDPoPTestRouter(claims *domain.TokenClaims, verifier middleware.DPoPVerifier) *gin.Engine {
	r := gin.New()

	// Inject claims into context (simulates AuthMiddleware).
	r.Use(func(c *gin.Context) {
		if claims != nil {
			c.Set("claims", claims)
			c.Set("user_id", claims.Subject)
		}
		c.Next()
	})

	r.Use(middleware.DPoPMiddleware(verifier))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestDPoPMiddleware(t *testing.T) {
	const correctThumbprint = "abc123thumbprint"

	tests := []struct {
		name             string
		claims           *domain.TokenClaims
		verifier         *mockDPoPVerifier
		dpopHeader       string
		wantStatus       int
		wantBodyContains string
	}{
		{
			name: "bound token without DPoP proof header is rejected",
			claims: &domain.TokenClaims{
				Subject:        "user-1",
				DPoPThumbprint: correctThumbprint,
			},
			verifier:         &mockDPoPVerifier{thumbprint: correctThumbprint},
			dpopHeader:       "",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "missing DPoP proof header",
		},
		{
			name: "bound token with wrong key is rejected",
			claims: &domain.TokenClaims{
				Subject:        "user-2",
				DPoPThumbprint: correctThumbprint,
			},
			verifier:         &mockDPoPVerifier{thumbprint: "wrong-thumbprint"},
			dpopHeader:       "valid-proof-wrong-key",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "does not match token binding",
		},
		{
			name: "bound token with invalid proof is rejected",
			claims: &domain.TokenClaims{
				Subject:        "user-3",
				DPoPThumbprint: correctThumbprint,
			},
			verifier:         &mockDPoPVerifier{err: errors.New("bad signature")},
			dpopHeader:       "invalid-proof",
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "invalid DPoP proof",
		},
		{
			name: "bound token with correct proof passes",
			claims: &domain.TokenClaims{
				Subject:        "user-4",
				DPoPThumbprint: correctThumbprint,
			},
			verifier:   &mockDPoPVerifier{thumbprint: correctThumbprint},
			dpopHeader: "valid-proof-correct-key",
			wantStatus: http.StatusOK,
		},
		{
			name: "unbound Bearer token passes without DPoP header",
			claims: &domain.TokenClaims{
				Subject:        "user-5",
				DPoPThumbprint: "",
			},
			verifier:   &mockDPoPVerifier{thumbprint: "anything"},
			dpopHeader: "",
			wantStatus: http.StatusOK,
		},
		{
			name:       "no claims in context passes through",
			claims:     nil,
			verifier:   &mockDPoPVerifier{},
			dpopHeader: "",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := newDPoPTestRouter(tc.claims, tc.verifier)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			if tc.dpopHeader != "" {
				req.Header.Set("DPoP", tc.dpopHeader)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantBodyContains)
			}
		})
	}
}
