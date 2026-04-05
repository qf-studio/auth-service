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

type mockAPIKeyValidator struct {
	validateFn func(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error)
}

func (m *mockAPIKeyValidator) ValidateAPIKey(ctx context.Context, rawKey string) (*middleware.APIKeyInfo, error) {
	if m.validateFn != nil {
		return m.validateFn(ctx, rawKey)
	}
	return &middleware.APIKeyInfo{
		ClientID:  "client-123",
		Scopes:    []string{"read:users"},
		RateLimit: 1000,
	}, nil
}

func setupAPIKeyRouter(validator middleware.APIKeyValidator) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.APIKeyMiddleware(validator))
	r.GET("/test", func(c *gin.Context) {
		claims, exists := c.Get("claims")
		if exists {
			tc := claims.(*domain.TokenClaims)
			c.JSON(http.StatusOK, gin.H{"subject": tc.Subject, "authenticated": true})
		} else {
			c.JSON(http.StatusOK, gin.H{"authenticated": false})
		}
	})
	return r
}

func TestAPIKeyMiddleware_ValidKey(t *testing.T) {
	r := setupAPIKeyRouter(&mockAPIKeyValidator{})
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_validkey123")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":true`)
	assert.Contains(t, w.Body.String(), `"subject":"client-123"`)
	assert.Equal(t, "1000", w.Header().Get("X-RateLimit-Limit"))
}

func TestAPIKeyMiddleware_NoHeader_FallThrough(t *testing.T) {
	r := setupAPIKeyRouter(&mockAPIKeyValidator{})
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"authenticated":false`)
}

func TestAPIKeyMiddleware_InvalidKey(t *testing.T) {
	validator := &mockAPIKeyValidator{
		validateFn: func(_ context.Context, _ string) (*middleware.APIKeyInfo, error) {
			return nil, fmt.Errorf("invalid key")
		},
	}
	r := setupAPIKeyRouter(validator)
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	req.Header.Set("X-API-Key", "qf_ak_badkey")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}
