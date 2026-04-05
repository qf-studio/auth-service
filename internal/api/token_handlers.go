package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// TokenHandlers groups HTTP handlers for token management endpoints.
type TokenHandlers struct {
	token         TokenService
	dpopToken     DPoPTokenService
	dpopValidator DPoPProofValidator
	requestURIFn  func(*gin.Context) string
}

// NewTokenHandlers creates a new TokenHandlers with the given services.
// dpopToken and dpopValidator may be nil when DPoP is disabled.
func NewTokenHandlers(token TokenService, dpopToken DPoPTokenService, dpopValidator DPoPProofValidator, requestURIFn func(*gin.Context) string) *TokenHandlers {
	return &TokenHandlers{
		token:         token,
		dpopToken:     dpopToken,
		dpopValidator: dpopValidator,
		requestURIFn:  requestURIFn,
	}
}

// Token handles POST /auth/token — dispatches based on grant_type.
// If a DPoP header is present and DPoP is enabled, the proof is validated
// and the issued token is bound to the DPoP key via the cnf.jkt claim.
func (h *TokenHandlers) Token(c *gin.Context) {
	req := c.MustGet("validated_request").(*domain.TokenRequest)

	// Check for DPoP proof header.
	dpopThumbprint, err := h.extractDPoPThumbprint(c)
	if err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest,
			"invalid DPoP proof: "+err.Error())
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

func (h *TokenHandlers) tokenStandard(c *gin.Context, req *domain.TokenRequest) (*AuthResult, error) {
	switch req.GrantType {
	case "refresh_token":
		return h.token.Refresh(c.Request.Context(), req.RefreshToken)
	case "client_credentials":
		return h.token.ClientCredentials(c.Request.Context(), req.ClientID, req.ClientSecret)
	default:
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "unsupported grant_type")
		return nil, nil
	}
}

func (h *TokenHandlers) tokenWithDPoP(c *gin.Context, req *domain.TokenRequest, thumbprint string) (*AuthResult, error) {
	switch req.GrantType {
	case "refresh_token":
		return h.dpopToken.RefreshDPoP(c.Request.Context(), req.RefreshToken, thumbprint)
	case "client_credentials":
		return h.dpopToken.ClientCredentialsDPoP(c.Request.Context(), req.ClientID, req.ClientSecret, thumbprint)
	default:
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "unsupported grant_type")
		return nil, nil
	}
}

// extractDPoPThumbprint extracts and validates the DPoP proof from the request header.
// Returns empty string if no DPoP header is present (non-DPoP request).
func (h *TokenHandlers) extractDPoPThumbprint(c *gin.Context) (string, error) {
	dpopHeader := c.GetHeader("DPoP")
	if dpopHeader == "" {
		return "", nil
	}

	if h.dpopValidator == nil || !h.dpopValidator.Enabled() {
		return "", nil
	}

	httpURI := ""
	if h.requestURIFn != nil {
		httpURI = h.requestURIFn(c)
	}

	thumbprint, err := h.dpopValidator.ValidateProof(c.Request.Context(), dpopHeader, c.Request.Method, httpURI)
	if err != nil {
		return "", err
	}

	return thumbprint, nil
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
