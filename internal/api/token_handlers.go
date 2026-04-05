package api

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// TokenHandlers groups HTTP handlers for token management endpoints.
type TokenHandlers struct {
	token TokenService
	dpop  DPoPService
}

// NewTokenHandlers creates a new TokenHandlers with the given TokenService and optional DPoPService.
func NewTokenHandlers(token TokenService, dpop DPoPService) *TokenHandlers {
	return &TokenHandlers{token: token, dpop: dpop}
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

	var result *AuthResult

	if dpopThumbprint != "" && h.dpopToken != nil {
		// DPoP-bound token issuance.
		result, err = h.tokenWithDPoP(c, req, dpopThumbprint)
	} else {
		// Standard Bearer token issuance.
		result, err = h.tokenStandard(c, req)
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

	httpURI := requestURI(c)
	claims, err := h.dpop.ValidateProof(c.Request.Context(), proofJWT, c.Request.Method, httpURI)
	if err != nil {
		return "", err
	}

	return claims.JKTThumbprint, nil
}

// requestURI reconstructs the full request URI for DPoP htu matching.
func requestURI(c *gin.Context) string {
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	return fmt.Sprintf("%s://%s%s", scheme, c.Request.Host, c.Request.URL.Path)
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
