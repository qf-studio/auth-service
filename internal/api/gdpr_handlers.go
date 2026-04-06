package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// GDPRHandlers groups HTTP handlers for public GDPR self-service endpoints.
type GDPRHandlers struct {
	gdpr GDPRService
}

// NewGDPRHandlers creates a new GDPRHandlers with the given GDPRService.
func NewGDPRHandlers(gdpr GDPRService) *GDPRHandlers {
	return &GDPRHandlers{gdpr: gdpr}
}

// Export handles GET /auth/me/export.
// Returns the authenticated user's data export (GDPR Article 20 - right to data portability).
func (h *GDPRHandlers) Export(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	data, err := h.gdpr.ExportUserData(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, data)
}

// DeleteAccount handles DELETE /auth/me.
// Initiates account deletion for the authenticated user (GDPR Article 17 - right to erasure).
func (h *GDPRHandlers) DeleteAccount(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	resp, err := h.gdpr.DeleteAccount(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, resp)
}

// ListConsent handles GET /auth/me/consent.
// Returns all consent records for the authenticated user.
func (h *GDPRHandlers) ListConsent(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	consents, err := h.gdpr.ListConsent(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, consents)
}

// GrantConsent handles POST /auth/me/consent.
// Grants a new consent record for the authenticated user.
func (h *GDPRHandlers) GrantConsent(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	var req GrantConsentRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	consent, err := h.gdpr.GrantConsent(c.Request.Context(), userID, req.Type)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, consent)
}

// RevokeConsent handles DELETE /auth/me/consent/:type.
// Revokes a specific consent for the authenticated user.
func (h *GDPRHandlers) RevokeConsent(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	consentType := c.Param("type")
	if consentType == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "consent type is required")
		return
	}

	if err := h.gdpr.RevokeConsent(c.Request.Context(), userID, consentType); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "consent revoked"})
}
