package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// DefaultInactivityThreshold is the maximum allowed duration since last
// session activity before the session is considered inactive.
const DefaultInactivityThreshold = 1 * time.Hour

// SessionChecker defines the session operations required by SessionActivity
// middleware. The session service implements this interface.
type SessionChecker interface {
	// LastActivityAt returns the last activity timestamp for the given user's
	// session. Returns an error if the session does not exist.
	LastActivityAt(ctx context.Context, userID string) (time.Time, error)

	// UpdateActivity updates the last activity timestamp for the given user's
	// session to the current time.
	UpdateActivity(ctx context.Context, userID string) error
}

// SessionActivity returns a Gin middleware that enforces session inactivity
// timeouts. It must be placed after AuthMiddleware so that claims and user_id
// are available in context.
//
// On each request it:
//  1. Retrieves the user ID from context (set by AuthMiddleware)
//  2. Checks last_activity_at via SessionChecker
//  3. If the elapsed time exceeds the inactivity threshold, returns 401
//     requiring reauthentication
//  4. Otherwise updates last_activity_at via SessionChecker
func SessionActivity(checker SessionChecker, threshold time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.GetString(userIDContextKey)
		if userID == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"authentication required")
			return
		}

		lastActivity, err := checker.LastActivityAt(c.Request.Context(), userID)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"session not found")
			return
		}

		if time.Since(lastActivity) > threshold {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"session expired due to inactivity, please reauthenticate")
			return
		}

		if err := checker.UpdateActivity(c.Request.Context(), userID); err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"failed to update session activity")
			return
		}

		c.Next()
	}
}
