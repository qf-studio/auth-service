package api

import (
	"net/http"

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

	switch req.GrantType {
	case domain.GrantTypeTokenExchange:
		h.handleTokenExchange(c, req)
	default:
		h.handleStandardGrant(c, req)
	}
}

// handleStandardGrant dispatches refresh_token and client_credentials grants.
func (h *TokenHandlers) handleStandardGrant(c *gin.Context, req *domain.TokenRequest) {
	var result *AuthResult
	var err error

	switch req.GrantType {
	case "refresh_token":
		result, err = h.token.Refresh(c.Request.Context(), req.RefreshToken)
	case "client_credentials":
		result, err = h.token.ClientCredentials(c.Request.Context(), req.ClientID, req.ClientSecret)
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

// handleTokenExchange handles the RFC 8693 token exchange grant type.
func (h *TokenHandlers) handleTokenExchange(c *gin.Context, req *domain.TokenRequest) {
	exchangeReq := &TokenExchangeRequest{
		SubjectToken:       req.SubjectToken,
		SubjectTokenType:   req.SubjectTokenType,
		ActorToken:         req.ActorToken,
		ActorTokenType:     req.ActorTokenType,
		RequestedTokenType: req.RequestedTokenType,
		Audience:           req.Audience,
		Scope:              req.Scope,
	}

	result, err := h.token.TokenExchange(c.Request.Context(), exchangeReq)
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
