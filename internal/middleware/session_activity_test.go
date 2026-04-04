package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// mockSessionChecker implements middleware.SessionChecker for testing.
type mockSessionChecker struct {
	lastActivity    time.Time
	lastActivityErr error
	updateErr       error
	updatedUserID   string
}

func (m *mockSessionChecker) LastActivityAt(_ context.Context, _ string) (time.Time, error) {
	return m.lastActivity, m.lastActivityErr
}

func (m *mockSessionChecker) UpdateActivity(_ context.Context, userID string) error {
	m.updatedUserID = userID
	return m.updateErr
}

// newSessionActivityTestRouter creates a router with AuthMiddleware + SessionActivity.
func newSessionActivityTestRouter(v middleware.TokenValidator, sc middleware.SessionChecker, threshold time.Duration) *gin.Engine {
	r := gin.New()
	r.Use(middleware.AuthMiddleware(v))
	r.Use(middleware.SessionActivity(sc, threshold))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	return r
}

func TestSessionActivity(t *testing.T) {
	validClaims := &domain.TokenClaims{
		Subject:    "user-123",
		Roles:      []string{"user"},
		ClientType: domain.ClientTypeUser,
		TokenID:    "tok-abc",
	}
	threshold := 1 * time.Hour

	tests := []struct {
		name             string
		authHeader       string
		validator        *mockValidator
		checker          *mockSessionChecker
		wantStatus       int
		wantBodyContains string
		wantUpdated      bool
	}{
		{
			name:       "active session passes and activity updated",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivity: time.Now().Add(-30 * time.Minute), // 30 min ago, within threshold
			},
			wantStatus:       http.StatusOK,
			wantBodyContains: "ok",
			wantUpdated:      true,
		},
		{
			name:       "inactive session rejected with 401",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivity: time.Now().Add(-2 * time.Hour), // 2 hours ago, exceeds threshold
			},
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "reauthenticate",
			wantUpdated:      false,
		},
		{
			name:       "session exactly at threshold boundary is rejected",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivity: time.Now().Add(-1*time.Hour - 1*time.Second), // just past threshold
			},
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "reauthenticate",
			wantUpdated:      false,
		},
		{
			name:       "session not found returns 401",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivityErr: errors.New("session not found"),
			},
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "session not found",
			wantUpdated:      false,
		},
		{
			name:       "update activity failure returns 401",
			authHeader: "Bearer qf_at_validtoken",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivity: time.Now().Add(-5 * time.Minute),
				updateErr:    errors.New("redis unavailable"),
			},
			wantStatus:       http.StatusUnauthorized,
			wantBodyContains: "failed to update session activity",
			wantUpdated:      true, // UpdateActivity is called but returns error
		},
		{
			name:       "no auth token returns 401 from auth middleware before session check",
			authHeader: "",
			validator:  &mockValidator{claims: validClaims},
			checker: &mockSessionChecker{
				lastActivity: time.Now(),
			},
			wantStatus:  http.StatusUnauthorized,
			wantUpdated: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			router := newSessionActivityTestRouter(tc.validator, tc.checker, threshold)

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
			if tc.wantUpdated {
				assert.Equal(t, "user-123", tc.checker.updatedUserID,
					"UpdateActivity should have been called with the user ID")
			} else if tc.checker.updatedUserID != "" && !tc.wantUpdated {
				t.Errorf("UpdateActivity should not have been called, but was called with %q",
					tc.checker.updatedUserID)
			}
		})
	}
}

func TestSessionActivity_WithoutAuthMiddleware(t *testing.T) {
	// Test that SessionActivity returns 401 when no user_id is in context
	// (i.e., when AuthMiddleware has not run).
	checker := &mockSessionChecker{
		lastActivity: time.Now(),
	}

	r := gin.New()
	r.Use(middleware.SessionActivity(checker, 1*time.Hour))
	r.GET("/protected", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/protected", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication required")
}
