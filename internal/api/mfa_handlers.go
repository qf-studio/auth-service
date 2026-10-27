package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MFAHandlers groups HTTP handlers for MFA endpoints.
type MFAHandlers struct {
	mfa     MFAService
	session SessionService
	log     *zap.Logger
}

// NewMFAHandlers creates a new MFAHandlers with the given MFAService and an
// optional SessionService for session creation once the MFA challenge passes.
// A nil logger is replaced by a no-op logger.
func NewMFAHandlers(mfa MFAService, session SessionService, log *zap.Logger) *MFAHandlers {
	if log == nil {
		log = zap.NewNop()
	}
	return &MFAHandlers{mfa: mfa, session: session, log: log}
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

	recordSession(c, h.session, h.log, result.UserID)

	c.JSON(http.StatusOK, result)
}

// mfaDisableRequest is the request body for disabling MFA. Both the current
// password and a second-factor code are required.
type mfaDisableRequest struct {
	Password string `json:"password"  binding:"required"`
	Code     string `json:"code"      binding:"required"`
	CodeType string `json:"code_type"` // "totp" (default) or "backup"
}

// Disable handles POST /auth/mfa/disable.
// Removes MFA for the authenticated user after verifying the current password
// and a current TOTP code or an unused backup code.
func (h *MFAHandlers) Disable(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	var req mfaDisableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := h.mfa.DisableWithVerification(c.Request.Context(), userID, req.Password, req.Code, req.CodeType); err != nil {
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
