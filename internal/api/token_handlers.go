package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// TokenHandlers groups HTTP handlers for token management endpoints.
type TokenHandlers struct {
	token TokenService
}

// NewTokenHandlers creates a new TokenHandlers with the given TokenService.
func NewTokenHandlers(token TokenService) *TokenHandlers {
	return &TokenHandlers{token: token}
}

// Token handles POST /auth/token — dispatches based on grant_type.
func (h *TokenHandlers) Token(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.TokenRequest)

	var result *AuthResult
	var err error

	switch req.GrantType {
	case "refresh_token":
		result, err = h.token.Refresh(c.Request.Context(), req.RefreshToken)
	case "client_credentials":
		var scopes []string
		if req.Scope != "" {
			scopes = strings.Fields(req.Scope)
		}
		result, err = h.token.ClientCredentials(c.Request.Context(), req.ClientID, req.ClientSecret, scopes)
	default:
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "unsupported grant_type")
		return
	}

	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Revoke handles POST /auth/revoke.
func (h *TokenHandlers) Revoke(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.RevokeRequest)

	if err := h.token.Revoke(c.Request.Context(), req.Token); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Token revoked"})
}

// JWKS handles GET /.well-known/jwks.json.
func (h *TokenHandlers) JWKS(c *gin.Context) {
	jwks, err := h.token.JWKS(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, jwks)
}
