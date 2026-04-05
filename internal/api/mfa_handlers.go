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

// Enroll handles POST /auth/mfa/enroll.
// Protected — requires authenticated user.
// Returns the TOTP secret URI (for QR code) and backup codes.
func (h *MFAHandlers) Enroll(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	result, err := h.mfa.Enroll(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Confirm handles POST /auth/mfa/confirm.
// Protected — requires authenticated user.
// Activates a pending MFA enrollment by verifying a TOTP code.
func (h *MFAHandlers) Confirm(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	req := c.MustGet("validated_request").(*domain.MFAConfirmRequest)

	if err := h.mfa.Confirm(c.Request.Context(), userID, req.Code); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "MFA enabled"})
}

// Verify handles POST /auth/mfa/verify.
// Public — consumes an mfa_token (issued during login) plus a TOTP or backup code,
// and returns a full token pair on success.
func (h *MFAHandlers) Verify(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.MFAVerifyRequest)

	result, err := h.mfa.Verify(c.Request.Context(), req.MFAToken, req.Code)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
