package api

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// OAuthHandlers groups HTTP handlers for OAuth / social login endpoints.
type OAuthHandlers struct {
	oauth OAuthService
}

// NewOAuthHandlers creates a new OAuthHandlers with the given OAuthService.
func NewOAuthHandlers(oauth OAuthService) *OAuthHandlers {
	return &OAuthHandlers{oauth: oauth}
}

// Initiate handles GET /auth/oauth/:provider.
// Generates a CSRF state token and PKCE code verifier, then redirects the
// user-agent to the provider's authorization URL.
func (h *OAuthHandlers) Initiate(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider")
		return
	}

	state, err := randomToken(32)
	if err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError, "internal server error")
		return
	}

	codeVerifier, err := randomToken(32)
	if err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError, "internal server error")
		return
	}

	authURL, err := h.oauth.GetAuthURL(c.Request.Context(), provider, state, codeVerifier)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.Redirect(http.StatusFound, authURL)
}

// Callback handles GET /auth/oauth/:provider/callback.
// Exchanges the authorization code for tokens, links or creates the user
// account, and returns a token pair (or MFA challenge).
func (h *OAuthHandlers) Callback(c *gin.Context) {
	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider")
		return
	}

	code := c.Query("code")
	if code == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing authorization code")
		return
	}

	state := c.Query("state")
	if state == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing state parameter")
		return
	}

	// Check for provider-reported errors (e.g., user denied consent).
	if errParam := c.Query("error"); errParam != "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "oauth error: "+errParam)
		return
	}

	result, err := h.oauth.HandleCallback(c.Request.Context(), provider, code, state)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// ListProviders handles GET /auth/me/oauth.
// Returns the OAuth providers linked to the authenticated user's account.
func (h *OAuthHandlers) ListProviders(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	providers, err := h.oauth.ListLinkedProviders(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// UnlinkProvider handles DELETE /auth/me/oauth/:provider.
// Removes the link between the authenticated user and the named provider.
func (h *OAuthHandlers) UnlinkProvider(c *gin.Context) {
	userID := c.GetString("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized, "missing user identity")
		return
	}

	provider := c.Param("provider")
	if provider == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "missing provider")
		return
	}

	if err := h.oauth.UnlinkProvider(c.Request.Context(), userID, provider); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Provider unlinked"})
}

// randomToken generates a URL-safe base64-encoded random token of n bytes.
func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(b), nil
}
