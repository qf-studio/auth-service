package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SAMLHandlers groups HTTP handlers for public SAML SSO endpoints.
type SAMLHandlers struct {
	saml SAMLService
}

// NewSAMLHandlers creates a new SAMLHandlers with the given SAMLService.
func NewSAMLHandlers(saml SAMLService) *SAMLHandlers {
	return &SAMLHandlers{saml: saml}
}

// Metadata handles GET /auth/saml/metadata.
// Returns the SP metadata XML document for the specified IdP (or default).
func (h *SAMLHandlers) Metadata(c *gin.Context) {
	idpID := c.DefaultQuery("idp_id", "")

	result, err := h.saml.GetMetadata(c.Request.Context(), idpID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.Data(http.StatusOK, "application/samlmetadata+xml", result.XML)
}

// Login handles GET /auth/saml/login.
// Initiates the SAML SSO flow by redirecting the user to the IdP.
func (h *SAMLHandlers) Login(c *gin.Context) {
	idpID := c.Query("idp_id")
	if idpID == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing idp_id parameter")
		return
	}

	relayState := c.DefaultQuery("relay_state", "")

	result, err := h.saml.InitiateSSO(c.Request.Context(), idpID, relayState)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.Redirect(http.StatusFound, result.RedirectURL)
}

// ACS handles POST /auth/saml/acs.
// Processes the SAML response from the IdP and issues a JWT token pair.
// The IdP sends a form-encoded POST with SAMLResponse and optional RelayState.
func (h *SAMLHandlers) ACS(c *gin.Context) {
	samlResponse := c.PostForm("SAMLResponse")
	if samlResponse == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing SAMLResponse parameter")
		return
	}

	relayState := c.PostForm("RelayState")

	result, err := h.saml.ProcessResponse(c.Request.Context(), samlResponse, relayState)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
