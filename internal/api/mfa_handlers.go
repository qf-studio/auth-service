package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MFAHandlers groups HTTP handlers for MFA endpoints.
type MFAHandlers struct {
	mfa MFAService
}

// NewMFAHandlers creates a new MFAHandlers with the given MFAService.
func NewMFAHandlers(mfa MFAService) *MFAHandlers {
	return &MFAHandlers{mfa: mfa}
}

// Setup handles POST /auth/mfa/setup.
// Initiates TOTP enrollment for the authenticated user.
func (h *MFAHandlers) Setup(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	email := c.GetString("user_email")

	result, err := h.mfa.InitiateEnrollment(c.Request.Context(), userID, email)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// mfaConfirmRequest is the request body for confirming MFA enrollment.
type mfaConfirmRequest struct {
	Code string `json:"code" binding:"required"`
}

// Confirm handles POST /auth/mfa/confirm.
// Validates a TOTP code to confirm enrollment and returns backup codes.
func (h *MFAHandlers) Confirm(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	var req mfaConfirmRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	backupCodes, err := h.mfa.ConfirmEnrollment(c.Request.Context(), userID, req.Code)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, MFAConfirmResult{BackupCodes: backupCodes})
}

// mfaVerifyRequest is the request body for verifying MFA during login.
type mfaVerifyRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
	Code     string `json:"code"      binding:"required"`
	CodeType string `json:"code_type"` // "totp" (default) or "backup"
}

// Verify handles POST /auth/mfa/verify.
// Completes the MFA challenge during login by verifying TOTP or backup code.
func (h *MFAHandlers) Verify(c *gin.Context) {
	var req mfaVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	result, err := h.mfa.CompleteMFALogin(c.Request.Context(), req.MFAToken, req.Code, req.CodeType)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Disable handles POST /auth/mfa/disable.
// Removes MFA for the authenticated user.
func (h *MFAHandlers) Disable(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	if err := h.mfa.Disable(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA disabled"})
}

// Status handles GET /auth/mfa/status.
// Returns the MFA status for the authenticated user.
func (h *MFAHandlers) Status(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	status, err := h.mfa.GetStatus(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, status)
}
