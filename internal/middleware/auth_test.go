package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockValidator implements middleware.TokenValidator for testing.
type mockValidator struct {
	claims    *domain.TokenClaims
	validateErr error
	revoked   bool
	revokeErr error
}

func (m *mockValidator) ValidateToken(_ context.Context, _ string) (*domain.TokenClaims, error) {
	return m.claims, m.validateErr
}

func (m *mockValidator) IsRevoked(_ context.Context, _ string) (bool, error) {
	return m.revoked, m.revokeErr
}

func newAuthTestRouter(v middleware.TokenValidator) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.GET("/protected", func(c *gin.Context) {
		userID := c.GetString("user_id")
		c.String(http.StatusOK, userID)
	})
	return r
}

func TestAuthMiddleware(t *testing.T) {
	validClaims := &domain.TokenClaims{
		Subject:    "user-123",
		Roles:      []string{"user"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-abc",
	}

	tests := []struct {
		name           string
		authHeader     string
		validator      *mockValidator
		wantStatus     int
		wantBodyContains string
	}{
		{
			name:       "valid token passes, claims set in context",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			wantStatus: http.StatusOK,
			wantBodyContains: "user-123",
		},
		{
			name:       "missing Authorization header returns 401",
			authHeader: "",
			validator:  &mockValidator{claims: validClaims},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "malformed header (no Bearer) returns 401",
			authHeader: "Token qf_at_something",
			validator:  &mockValidator{claims: validClaims},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token without qf_at_ prefix returns 401",
			authHeader: "Bearer rawtoken_no_prefix",
			validator:  &mockValidator{claims: validClaims},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "token that fails validation returns 401",
			authHeader: "Bearer qf_at_badtoken",
			validator:  &mockValidator{validateErr: errors.New("signature invalid")},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "revoked token returns 401",
			authHeader: "Bearer qf_at_revokedtoken",
			validator:  &mockValidator{claims: validClaims, revoked: true},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "revocation check error returns 401",
			authHeader: "Bearer qf_at_token",
			validator:  &mockValidator{claims: validClaims, revokeErr: errors.New("redis unavailable")},
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "expired token (ValidateToken error) returns 401",
			authHeader: "Bearer qf_at_expiredtoken",
			validator:  &mockValidator{validateErr: errors.New("token expired")},
			wantStatus: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := newAuthTestRouter(tc.validator)

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			router.ServeHTTP(w, req)

			assert.Equal(t, tc.wantStatus, w.Code)
			if tc.wantBodyContains != "" {
				assert.Contains(t, w.Body.String(), tc.wantBodyContains)
			}
		})
	}
}

func TestAuthMiddleware_ClaimsStoredInContext(t *testing.T) {
	claims := &domain.TokenClaims{
		Subject:    "svc-456",
		Roles:      []string{"service"},
		Scopes:     []string{"read:users", "write:tokens"},
		ClientType: domain.ClientTypeService,
		TokenID:    "tok-xyz",
	}
	v := &mockValidator{claims: claims}

	var capturedClaims *domain.TokenClaims
	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.GET("/check", func(c *gin.Context) {
		got, err := middleware.GetClaims(c)
		require.NoError(t, err)
		capturedClaims = got
		c.Status(http.StatusOK)
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/check", http.NoBody)
	req.Header.Set("Authorization", "Bearer qf_at_token")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedClaims)
	assert.Equal(t, "svc-456", capturedClaims.Subject)
	assert.Equal(t, []string{"read:users", "write:tokens"}, capturedClaims.Scopes)
	assert.Equal(t, domain.ClientTypeService, capturedClaims.ClientType)
}
