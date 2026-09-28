package api

import (
	"errors"
	"net/http"
	"strings"

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

	// If MFA is required, return the challenge without creating a session.
	if result.MFARequired {
		c.JSON(http.StatusOK, result)
		return
	}

	// Create a session record if the session service is available.
	if h.session != nil && result.UserID != "" {
		ip := c.ClientIP()
		ua := c.GetHeader("User-Agent")
		// Session creation is best-effort; login should not fail if session
		// tracking is unavailable.
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

// VerifyEmail handles POST /auth/verify-email.
func (h *AuthHandlers) VerifyEmail(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.VerifyEmailRequest)

	// Any failure (unknown, expired) maps to 400 — verification tokens aren't
	// an enumeration risk the way password reset is, so there's no need to
	// mask the outcome. Success is idempotent: already-verified users also get 200.
	if err := h.auth.VerifyEmail(c.Request.Context(), req.Token); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid or expired verification token")
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Email verified"})
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

// UpdateProfile handles PUT /auth/me.
func (h *AuthHandlers) UpdateProfile(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	req := c.MustGet("validated_request").(*domain.ProfileUpdateRequest)
	name := strings.TrimSpace(req.Name)

	user, err := h.auth.UpdateProfile(c.Request.Context(), userID, name)
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

// RequestEmailChange handles POST /auth/me/email. It initiates a change of
// the authenticated user's account email, pending confirmation from the new
// address (see AuthHandlers.ConfirmEmailChange).
func (h *AuthHandlers) RequestEmailChange(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	req := c.MustGet("validated_request").(*domain.EmailChangeRequest)

	result, err := h.auth.RequestEmailChange(c.Request.Context(), userID, req.NewEmail, req.Password)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusAccepted, result)
}

// ConfirmEmailChange handles POST /auth/email-change/confirm. The token is
// the one sent to the new address by RequestEmailChange.
func (h *AuthHandlers) ConfirmEmailChange(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.EmailChangeConfirmRequest)

	if err := h.auth.ConfirmEmailChange(c.Request.Context(), req.Token); err != nil {
		// An unknown or already-consumed token isn't an enumeration risk (the
		// caller already has a token, valid or not), so it's reported the
		// same way VerifyEmail reports a bad token: 400, not 404. Expired
		// still falls through to handleServiceError's 410.
		if errors.Is(err, ErrNotFound) {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid or already-used email change token")
			return
		}
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "changed"})
}

// RevertEmailChange handles POST /auth/email-change/revert. The token is the
// one sent to the original address by RequestEmailChange; it reverts a
// pending or already-confirmed email change.
func (h *AuthHandlers) RevertEmailChange(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.EmailChangeRevertRequest)

	if err := h.auth.RevertEmailChange(c.Request.Context(), req.Token); err != nil {
		// Same reasoning as ConfirmEmailChange above: unknown/consumed -> 400,
		// expired stays 410 via handleServiceError.
		if errors.Is(err, ErrNotFound) {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid or already-used email revert token")
			return
		}
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "reverted"})
}

// Logout handles POST /auth/logout.
func (h *AuthHandlers) Logout(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	token := extractBearerToken(c)

	// The refresh token is optional and not validated via the shared
	// middleware (an absent/empty body is valid here); ignore bind errors
	// and fall back to the zero value.
	var req domain.LogoutRequest
	_ = c.ShouldBindJSON(&req)

	if err := h.auth.Logout(c.Request.Context(), userID, token, req.RefreshToken); err != nil {
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

	// ErrInvalidPassword indicates a password-verification step failed (e.g.
	// the password supplied to POST /auth/me/email didn't match). Distinct
	// from ErrUnauthorized: this maps to 403, not 401, since the caller is
	// already authenticated.
	ErrInvalidPassword = errors.New("invalid password")

	// ErrRateLimited indicates the caller has exceeded a service-level rate
	// limit (e.g. email-change requests per hour).
	ErrRateLimited = errors.New("rate limited")

	// ErrGone indicates the resource a token pointed to is no longer valid
	// because it has expired (as opposed to ErrNotFound's "never existed").
	ErrGone = errors.New("gone")

	// ErrEmailChangeUnconfigured indicates POST /auth/me/email was called
	// while EMAIL_ENABLED=true but the email-change confirm/revert URL
	// bases haven't been configured.
	ErrEmailChangeUnconfigured = errors.New("email change unconfigured")
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
	case errors.Is(err, ErrInvalidPassword):
		domain.RespondWithError(c, http.StatusForbidden, domain.CodeInvalidPassword, err.Error())
	case errors.Is(err, ErrRateLimited):
		domain.RespondWithError(c, http.StatusTooManyRequests, domain.CodeRateLimitExceded, err.Error())
	case errors.Is(err, ErrGone):
		domain.RespondWithError(c, http.StatusGone, domain.CodeGone, err.Error())
	case errors.Is(err, ErrEmailChangeUnconfigured):
		domain.RespondWithError(c, http.StatusServiceUnavailable, domain.CodeEmailChangeUnconfigured, err.Error())
	default:
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError, "internal server error")
	}
}
