package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AdminMFAHandlers groups HTTP handlers for admin MFA management endpoints.
type AdminMFAHandlers struct {
	mfa MFAService
}

// NewAdminMFAHandlers creates a new AdminMFAHandlers with the given MFAService.
func NewAdminMFAHandlers(mfa MFAService) *AdminMFAHandlers {
	return &AdminMFAHandlers{mfa: mfa}
}

// GetStatus handles GET /admin/users/:id/mfa.
// Returns the MFA status for a specific user.
func (h *AdminMFAHandlers) GetStatus(c *gin.Context) {
	userID := c.Param("id")

	status, err := h.mfa.GetStatus(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, status)
}

// Reset handles DELETE /admin/users/:id/mfa.
// Removes MFA for a specific user (admin reset).
func (h *AdminMFAHandlers) Reset(c *gin.Context) {
	userID := c.Param("id")

	if err := h.mfa.Disable(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA reset for user"})
}
