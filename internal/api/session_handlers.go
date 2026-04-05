package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SessionHandlers groups HTTP handlers for session management endpoints.
type SessionHandlers struct {
	session SessionService
}

// NewSessionHandlers creates a new SessionHandlers with the given SessionService.
func NewSessionHandlers(session SessionService) *SessionHandlers {
	return &SessionHandlers{session: session}
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

	if err := h.session.DeleteAllSessions(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "all sessions terminated"})
}
