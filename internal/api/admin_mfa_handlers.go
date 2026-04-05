package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AdminMFAHandlers groups HTTP handlers for admin MFA management endpoints.
type AdminMFAHandlers struct {
	mfa AdminMFAService
}

// NewAdminMFAHandlers creates a new AdminMFAHandlers with the given AdminMFAService.
func NewAdminMFAHandlers(mfa AdminMFAService) *AdminMFAHandlers {
	return &AdminMFAHandlers{mfa: mfa}
}

// GetStatus handles GET /admin/users/:id/mfa.
// Returns the MFA enrollment status for a specific user.
func (h *AdminMFAHandlers) GetStatus(c *gin.Context) {
	userID := c.Param("id")

	status, err := h.mfa.GetMFAStatus(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, status)
}

// Reset handles DELETE /admin/users/:id/mfa.
// Resets (disables) MFA for a specific user.
func (h *AdminMFAHandlers) Reset(c *gin.Context) {
	userID := c.Param("id")

	if err := h.mfa.ResetMFA(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA reset"})
}
