package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminConsentHandlers groups HTTP handlers for admin login/consent flow endpoints.
type AdminConsentHandlers struct {
	consent  ConsentService
	approval AdminClientApprovalService
}

// NewAdminConsentHandlers creates a new AdminConsentHandlers.
func NewAdminConsentHandlers(consent ConsentService, approval AdminClientApprovalService) *AdminConsentHandlers {
	return &AdminConsentHandlers{consent: consent, approval: approval}
}

// GetLoginRequest handles GET /admin/oauth/auth/requests/login.
// Returns details of a pending login request identified by login_challenge query param.
func (h *AdminConsentHandlers) GetLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing login_challenge parameter")
		return
	}

	info, err := h.consent.GetLoginRequest(c.Request.Context(), challenge)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}

// PutLoginRequest handles PUT /admin/oauth/auth/requests/login.
// Accepts or rejects a login request based on the "accept" query parameter.
//
//	PUT ?login_challenge=xxx&accept=true  → accept
//	PUT ?login_challenge=xxx&accept=false → reject
func (h *AdminConsentHandlers) PutLoginRequest(c *gin.Context) {
	challenge := c.Query("login_challenge")
	if challenge == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing login_challenge parameter")
		return
	}

	accept := c.DefaultQuery("accept", "true")

	if accept == "true" {
		var req AcceptLoginRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body: "+err.Error())
			return
		}

		resp, err := h.consent.AcceptLogin(c.Request.Context(), challenge, &req)
		if err != nil {
			handleServiceError(c, err)
			return
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	var req RejectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body: "+err.Error())
		return
	}

	resp, err := h.consent.RejectLogin(c.Request.Context(), challenge, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// GetConsentRequest handles GET /admin/oauth/auth/requests/consent.
// Returns details of a pending consent request identified by consent_challenge query param.
func (h *AdminConsentHandlers) GetConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing consent_challenge parameter")
		return
	}

	info, err := h.consent.GetConsentRequest(c.Request.Context(), challenge)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}

// PutConsentRequest handles PUT /admin/oauth/auth/requests/consent.
// Accepts or rejects a consent request based on the "accept" query parameter.
//
//	PUT ?consent_challenge=xxx&accept=true  → accept
//	PUT ?consent_challenge=xxx&accept=false → reject
func (h *AdminConsentHandlers) PutConsentRequest(c *gin.Context) {
	challenge := c.Query("consent_challenge")
	if challenge == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing consent_challenge parameter")
		return
	}

	accept := c.DefaultQuery("accept", "true")

	if accept == "true" {
		var req AcceptConsentRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body: "+err.Error())
			return
		}

		resp, err := h.consent.AcceptConsent(c.Request.Context(), challenge, &req)
		if err != nil {
			handleServiceError(c, err)
			return
		}
		c.JSON(http.StatusOK, resp)
		return
	}

	var req RejectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body: "+err.Error())
		return
	}

	resp, err := h.consent.RejectConsent(c.Request.Context(), challenge, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, resp)
}

// CreateThirdPartyClient handles POST /admin/clients (third-party approval workflow).
// Creates a new client that requires admin approval before it can be used.
func (h *AdminConsentHandlers) CreateThirdPartyClient(c *gin.Context) {
	var req CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	client, err := h.approval.CreateThirdPartyClient(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, client)
}

// ApproveClient handles GET /admin/clients/:id/approve.
// Approves a third-party client, enabling it for use.
func (h *AdminConsentHandlers) ApproveClient(c *gin.Context) {
	clientID := c.Param("id")

	info, err := h.approval.ApproveClient(c.Request.Context(), clientID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}
