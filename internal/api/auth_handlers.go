package api

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AuthHandlers groups HTTP handlers for authentication endpoints.
type AuthHandlers struct {
	auth    AuthService
	session SessionService
}

// NewAuthHandlers creates a new AuthHandlers with the given AuthService
// and an optional SessionService for session creation on login.
func NewAuthHandlers(auth AuthService, session SessionService) *AuthHandlers {
	return &AuthHandlers{auth: auth, session: session}
}

// Register handles POST /auth/register.
func (h *AuthHandlers) Register(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.RegisterRequest)

	user, err := h.auth.Register(c.Request.Context(), req.Email, req.Password, req.Name)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Login handles POST /auth/login.
func (h *AuthHandlers) Login(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.LoginRequest)

	result, err := h.auth.Login(c.Request.Context(), req.Email, req.Password)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	// Skip session creation for MFA challenges — auth isn't complete yet.
	if !result.MFARequired && h.session != nil && result.UserID != "" {
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		// Session creation is best-effort; login should not fail if session
		// tracking is unavailable.
		_, _ = h.session.CreateSession(c.Request.Context(), result.UserID, ip, ua)
	}

	c.JSON(http.StatusOK, result)
}

// VerifyMFA handles POST /auth/mfa/verify.
// Completes the second step of an MFA login flow.
func (h *AuthHandlers) VerifyMFA(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.MFAVerifyRequest)

	result, err := h.auth.VerifyMFALogin(c.Request.Context(), req.MFAToken, req.Code)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	// Create session after successful MFA verification.
	if h.session != nil && result.UserID != "" {
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		_, _ = h.session.CreateSession(c.Request.Context(), result.UserID, ip, ua)
	}

	c.JSON(http.StatusOK, result)
}

// ResetPassword handles POST /auth/password/reset.
func (h *AuthHandlers) ResetPassword(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.PasswordResetRequest)

	// Always return 202 to prevent email enumeration.
	_ = h.auth.ResetPassword(c.Request.Context(), req.Email)

	c.JSON(http.StatusAccepted, gin.H{"message": "If the email exists, a reset link has been sent"})
}

// ConfirmPasswordReset handles POST /auth/password/reset/confirm.
func (h *AuthHandlers) ConfirmPasswordReset(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.PasswordResetConfirmRequest)

	if err := h.auth.ConfirmPasswordReset(c.Request.Context(), req.Token, req.NewPassword); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password has been reset"})
}

// Me handles GET /auth/me.
func (h *AuthHandlers) Me(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	user, err := h.auth.GetMe(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// ChangePassword handles PUT /auth/me/password.
func (h *AuthHandlers) ChangePassword(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	req := c.MustGet("validated_request").(*domain.PasswordChangeRequest)

	if err := h.auth.ChangePassword(c.Request.Context(), userID, req.OldPassword, req.NewPassword); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password changed"})
}

// Logout handles POST /auth/logout.
func (h *AuthHandlers) Logout(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	token := extractBearerToken(c)

	if err := h.auth.Logout(c.Request.Context(), userID, token); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Logged out"})
}

// LogoutAll handles POST /auth/logout/all.
func (h *AuthHandlers) LogoutAll(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	if err := h.auth.LogoutAll(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "All sessions terminated"})
}

// extractBearerToken pulls the token from the Authorization header.
func extractBearerToken(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}

// Sentinel errors that service implementations should return.
var (
	ErrUnauthorized  = errors.New("unauthorized")
	ErrNotFound      = errors.New("not found")
	ErrConflict      = errors.New("conflict")
	ErrForbidden     = errors.New("forbidden")
	ErrInternalError = errors.New("internal error")
)

// handleServiceError maps service-layer sentinel errors to HTTP error responses.
func handleServiceError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, ErrUnauthorized):
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, err.Error())
	case errors.Is(err, ErrNotFound):
		domain.RespondWithError(c, http.StatusNotFound, domain.CodeNotFound, err.Error())
	case errors.Is(err, ErrConflict):
		domain.RespondWithError(c, http.StatusConflict, domain.CodeBadRequest, err.Error())
	case errors.Is(err, ErrForbidden):
		domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden, err.Error())
	default:
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError, "internal server error")
	}
}
