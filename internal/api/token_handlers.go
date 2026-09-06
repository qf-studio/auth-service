package api

import (
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// TokenHandlers groups HTTP handlers for token management endpoints.
type TokenHandlers struct {
	token             TokenService
	dpop              DPoPService
	trustedProxyCIDRs []*net.IPNet
}

// NewTokenHandlers creates a new TokenHandlers with the given TokenService and optional DPoPService.
// trustedProxyCIDRs controls when X-Forwarded-Proto / X-Forwarded-Host are honored while
// reconstructing the request URI for DPoP htu matching (see middleware.RequestURI).
func NewTokenHandlers(token TokenService, dpop DPoPService, trustedProxyCIDRs []*net.IPNet) *TokenHandlers {
	return &TokenHandlers{token: token, dpop: dpop, trustedProxyCIDRs: trustedProxyCIDRs}
}

// Token handles POST /auth/token — dispatches based on grant_type.
// If a DPoP header is present and the DPoP service is enabled, the proof is
// validated and the resulting JWK thumbprint is bound to the issued token.
func (h *TokenHandlers) Token(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.TokenRequest)

	// Extract DPoP proof if present.
	jktThumbprint, err := h.extractDPoPThumbprint(c)
	if err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest,
			fmt.Sprintf("invalid DPoP proof: %s", err))
		return
	}

	var result *AuthResult

	switch req.GrantType {
	case "refresh_token":
		if jktThumbprint != "" {
			result, err = h.token.RefreshWithDPoP(c.Request.Context(), req.RefreshToken, jktThumbprint)
		} else {
			result, err = h.token.Refresh(c.Request.Context(), req.RefreshToken)
		}
	case "client_credentials":
		if jktThumbprint != "" {
			result, err = h.token.ClientCredentialsWithDPoP(c.Request.Context(), req.ClientID, req.ClientSecret, jktThumbprint)
		} else {
			result, err = h.token.ClientCredentials(c.Request.Context(), req.ClientID, req.ClientSecret)
		}
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

// extractDPoPThumbprint validates the DPoP proof header (if present) and returns
// the JWK thumbprint. Returns empty string and nil error when no DPoP header is sent.
func (h *TokenHandlers) extractDPoPThumbprint(c *gin.Context) (string, error) {
	proofJWT := c.GetHeader("DPoP")
	if proofJWT == "" {
		return "", nil
	}

	if h.dpop == nil || !h.dpop.Enabled() {
		return "", fmt.Errorf("DPoP is not enabled on this server")
	}

	httpURI := middleware.RequestURI(c, h.trustedProxyCIDRs)
	claims, err := h.dpop.ValidateProof(c.Request.Context(), proofJWT, c.Request.Method, httpURI)
	if err != nil {
		return "", err
	}

	return claims.JKTThumbprint, nil
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
