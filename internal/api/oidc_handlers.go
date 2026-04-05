package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OIDCHandlers groups HTTP handlers for OpenID Connect provider endpoints.
type OIDCHandlers struct {
	oidc OIDCProviderService
}

// NewOIDCHandlers creates a new OIDCHandlers with the given OIDCProviderService.
func NewOIDCHandlers(oidc OIDCProviderService) *OIDCHandlers {
	return &OIDCHandlers{oidc: oidc}
}

// Discovery handles GET /.well-known/openid-configuration.
// Returns the OIDC discovery document per RFC 8414.
func (h *OIDCHandlers) Discovery(c *gin.Context) {
	doc, err := h.oidc.GetDiscovery(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, doc)
}

// Authorize handles GET /oauth/authorize.
// Initiates the OAuth2 authorization code flow. Validates the request parameters
// and returns a redirect URL (to the login/consent UI).
func (h *OIDCHandlers) Authorize(c *gin.Context) {
	var req AuthorizeRequest
	if err := c.ShouldBindQuery(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid authorization request: "+err.Error())
		return
	}

	resp, err := h.oidc.Authorize(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.Redirect(http.StatusFound, resp.RedirectTo)
}

// Token handles POST /oauth/token for the authorization_code grant type.
// Exchanges an authorization code for access, refresh, and ID tokens.
func (h *OIDCHandlers) Token(c *gin.Context) {
	var req CodeExchangeRequest
	if err := c.ShouldBind(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid token request: "+err.Error())
		return
	}

	if req.GrantType != "authorization_code" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "unsupported grant_type: only authorization_code is supported on this endpoint")
		return
	}

	resp, err := h.oidc.ExchangeCode(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	// Token responses must not be cached (RFC 6749 §5.1).
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.JSON(http.StatusOK, resp)
}

// UserInfo handles GET /userinfo.
// Returns claims about the authenticated user based on the access token scopes.
func (h *OIDCHandlers) UserInfo(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	info, err := h.oidc.GetUserInfo(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}
