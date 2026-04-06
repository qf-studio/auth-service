package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// AdminGDPRHandlers groups HTTP handlers for admin GDPR management endpoints.
type AdminGDPRHandlers struct {
	gdpr AdminGDPRService
}

// NewAdminGDPRHandlers creates a new AdminGDPRHandlers with the given AdminGDPRService.
func NewAdminGDPRHandlers(gdpr AdminGDPRService) *AdminGDPRHandlers {
	return &AdminGDPRHandlers{gdpr: gdpr}
}

// Export handles GET /admin/users/:id/export.
// Returns the full data export for a specific user.
func (h *AdminGDPRHandlers) Export(c *gin.Context) {
	userID := c.Param("id")

	data, err := h.gdpr.ExportUserData(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, data)
}

// AdminDeleteUserRequest is the optional request body for admin user deletion.
type AdminDeleteUserRequest struct {
	Force bool `json:"force"`
}

// Delete handles DELETE /admin/users/:id (GDPR deletion with optional force flag).
// Force=true skips the retention period and deletes immediately.
func (h *AdminGDPRHandlers) Delete(c *gin.Context) {
	userID := c.Param("id")

	var req AdminDeleteUserRequest
	// Body is optional; ignore bind errors (defaults to force=false).
	_ = c.ShouldBindJSON(&req)

	resp, err := h.gdpr.DeleteUser(c.Request.Context(), userID, req.Force)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, resp)
}

// ListConsent handles GET /admin/users/:id/consent.
// Returns all consent records for a specific user.
func (h *AdminGDPRHandlers) ListConsent(c *gin.Context) {
	userID := c.Param("id")

	consents, err := h.gdpr.ListUserConsent(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, consents)
}
