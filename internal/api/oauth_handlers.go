package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OAuthHandlers groups HTTP handlers for OAuth social login endpoints.
type OAuthHandlers struct {
	oauth OAuthService
}

// NewOAuthHandlers creates a new OAuthHandlers with the given OAuthService.
func NewOAuthHandlers(oauth OAuthService) *OAuthHandlers {
	return &OAuthHandlers{oauth: oauth}
}

// Redirect handles GET /auth/oauth/:provider.
// Generates the OAuth authorization URL and redirects the user to the provider.
func (h *OAuthHandlers) Redirect(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider parameter")
		return
	}

	result, err := h.oauth.GetAuthURL(c.Request.Context(), provider)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Callback handles GET /auth/oauth/:provider/callback.
// Exchanges the authorization code for tokens and issues a JWT pair.
func (h *OAuthHandlers) Callback(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider parameter")
		return
	}

	code := c.Query("code")
	if code == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing code parameter")
		return
	}

	state := c.Query("state")

	result, err := h.oauth.HandleCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListLinked handles GET /auth/me/oauth.
// Returns all OAuth accounts linked to the authenticated user.
func (h *OAuthHandlers) ListLinked(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	accounts, err := h.oauth.ListLinkedAccounts(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, accounts)
}

// Unlink handles DELETE /auth/me/oauth/:provider.
// Removes the OAuth link for the specified provider from the authenticated user.
func (h *OAuthHandlers) Unlink(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider parameter")
		return
	}

	if err := h.oauth.UnlinkAccount(c.Request.Context(), userID, provider); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "OAuth account unlinked"})
}
