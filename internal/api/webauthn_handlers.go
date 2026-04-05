package api

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebAuthnHandlers groups HTTP handlers for WebAuthn (FIDO2) endpoints.
type WebAuthnHandlers struct {
	webauthn WebAuthnService
}

// NewWebAuthnHandlers creates a new WebAuthnHandlers with the given WebAuthnService.
func NewWebAuthnHandlers(svc WebAuthnService) *WebAuthnHandlers {
	return &WebAuthnHandlers{webauthn: svc}
}

// BeginRegistration handles POST /auth/mfa/webauthn/register/begin.
// Starts the WebAuthn registration ceremony for the authenticated user.
func (h *WebAuthnHandlers) BeginRegistration(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}
	email := c.GetString("user_email")

	options, err := h.webauthn.BeginRegistration(c.Request.Context(), userID, email)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, options)
}

// FinishRegistration handles POST /auth/mfa/webauthn/register/finish.
// Completes the WebAuthn registration ceremony.
func (h *WebAuthnHandlers) FinishRegistration(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}
	email := c.GetString("user_email")

	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "failed to read request body")
		return
	}
	if len(body) == 0 {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "empty request body")
		return
	}

	if err := h.webauthn.FinishRegistration(c.Request.Context(), userID, email, body); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "WebAuthn credential registered"})
}

// webauthnLoginBeginRequest is the request body for beginning WebAuthn login.
type webauthnLoginBeginRequest struct {
	MFAToken string `json:"mfa_token" binding:"required"`
}

// BeginLogin handles POST /auth/mfa/webauthn/login/begin.
// Starts the WebAuthn login ceremony using the MFA token from the login challenge.
func (h *WebAuthnHandlers) BeginLogin(c *gin.Context) {
	var req webauthnLoginBeginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	options, err := h.webauthn.BeginLogin(c.Request.Context(), req.MFAToken)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, options)
}

// webauthnLoginVerifyRequest wraps the MFA token alongside the raw attestation response body.
type webauthnLoginVerifyRequest struct {
	MFAToken string `json:"mfa_token"`
}

// VerifyLogin handles POST /auth/mfa/webauthn/login/verify.
// Completes the WebAuthn login ceremony, verifying the assertion and issuing tokens.
func (h *WebAuthnHandlers) VerifyLogin(c *gin.Context) {
	// Read the raw body for the WebAuthn assertion response.
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "failed to read request body")
		return
	}
	if len(body) == 0 {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "empty request body")
		return
	}

	// Extract the mfa_token from the JSON body while keeping the full body for WebAuthn.
	var envelope struct {
		MFAToken string `json:"mfa_token"`
	}
	// Use a lenient parse — the body contains additional WebAuthn fields.
	_ = json.Unmarshal(body, &envelope)
	if envelope.MFAToken == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing mfa_token")
		return
	}

	result, err := h.webauthn.FinishLogin(c.Request.Context(), envelope.MFAToken, body)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListCredentials handles GET /auth/mfa/webauthn/credentials.
// Returns all active WebAuthn credentials for the authenticated user.
func (h *WebAuthnHandlers) ListCredentials(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	creds, err := h.webauthn.ListCredentials(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"credentials": creds})
}

// DeleteCredential handles DELETE /auth/mfa/webauthn/credentials/:id.
// Soft-deletes a WebAuthn credential by its UUID.
func (h *WebAuthnHandlers) DeleteCredential(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	credID := c.Param("id")
	if credID == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing credential id")
		return
	}

	if err := h.webauthn.DeleteCredential(c.Request.Context(), userID, credID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "WebAuthn credential deleted"})
}
