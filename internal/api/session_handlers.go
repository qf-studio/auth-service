package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SessionHandlers groups HTTP handlers for session management endpoints.
type SessionHandlers struct {
	session SessionService
	auth    AuthService
	log     *zap.Logger
}

// NewSessionHandlers creates a new SessionHandlers. The AuthService is used to
// revoke the user's refresh tokens when all sessions are terminated.
// A nil logger is replaced by a no-op logger.
func NewSessionHandlers(session SessionService, auth AuthService, log *zap.Logger) *SessionHandlers {
	if log == nil {
		log = zap.NewNop()
	}
	return &SessionHandlers{session: session, auth: auth, log: log}
}

// recordSession creates a session record for a completed login (password or
// MFA). It is a no-op when sessions are not configured or the user is
// unknown. A store failure must not fail a login that already issued tokens,
// so it is logged rather than returned.
func recordSession(c *gin.Context, svc SessionService, log *zap.Logger, userID string) {
	if svc == nil || userID == "" {
		return
	}
	if _, err := svc.CreateSession(c.Request.Context(), userID, c.ClientIP(), c.GetHeader("User-Agent")); err != nil {
		log.Error("failed to create session record",
			zap.String("user_id", userID),
			zap.Error(err),
		)
	}
}

// List handles GET /auth/sessions.
func (h *SessionHandlers) List(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	sessions, err := h.session.ListSessions(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, SessionList{Sessions: sessions})
}

// Delete handles DELETE /auth/sessions/:id.
func (h *SessionHandlers) Delete(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	sessionID := c.Param("id")

	if err := h.session.DeleteSession(c.Request.Context(), userID, sessionID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "session terminated"})
}

// DeleteAll handles DELETE /auth/sessions.
func (h *SessionHandlers) DeleteAll(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	// Revoke tokens first, through the same path as POST /auth/logout/all: a
	// session list entry means nothing if its refresh tokens stay valid. If
	// revocation fails the session records are kept so the caller can retry.
	if err := h.auth.LogoutAll(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	if err := h.session.DeleteAllSessions(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all sessions terminated"})
}
