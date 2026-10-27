package api

import (
	"errors"
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

// tokenErrorResponse is the RFC 6749 §5.2 error body.
type tokenErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// respondTokenError writes an RFC 6749 §5.2 error. The description is a fixed
// string per error code: nothing about which check failed (client, code
// binding, redirect URI, PKCE) reaches the caller (GH-528).
func respondTokenError(c *gin.Context, status int, code, description string) {
	c.Header("Cache-Control", "no-store")
	c.Header("Pragma", "no-cache")
	c.AbortWithStatusJSON(status, tokenErrorResponse{Error: code, ErrorDescription: description})
}

// Token handles POST /oauth/token for the authorization_code grant type.
// Exchanges an authorization code for access, refresh, and ID tokens.
// Failures use the RFC 6749 §5.2 body shape.
func (h *OIDCHandlers) Token(c *gin.Context) {
	var req CodeExchangeRequest
	if err := c.ShouldBind(&req); err != nil {
		respondTokenError(c, http.StatusBadRequest, "invalid_request", "The request is missing a required parameter or is malformed.")
		return
	}

	if req.GrantType != "authorization_code" {
		respondTokenError(c, http.StatusBadRequest, "unsupported_grant_type", "Only the authorization_code grant is supported on this endpoint.")
		return
	}

	resp, err := h.oidc.ExchangeCode(c.Request.Context(), &req)
	if err != nil {
		switch {
		case errors.Is(err, ErrInvalidClient):
			respondTokenError(c, http.StatusUnauthorized, "invalid_client", "Client authentication failed.")
		case errors.Is(err, ErrInvalidGrant):
			respondTokenError(c, http.StatusBadRequest, "invalid_grant", "The authorization code is invalid, expired, or was not issued for this request.")
		default:
			respondTokenError(c, http.StatusInternalServerError, "server_error", "The server encountered an unexpected error.")
		}
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

	// Scopes come from the verified access token, placed in the context by
	// AuthMiddleware. A missing claims entry yields no scopes, so the
	// service rejects the call for lack of openid.
	var scopes []string
	if v, ok := c.Get("claims"); ok {
		if claims, ok := v.(*domain.TokenClaims); ok {
			scopes = claims.Scopes
		}
	}

	info, err := h.oidc.GetUserInfo(c.Request.Context(), userID, scopes)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, info)
}
