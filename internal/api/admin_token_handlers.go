package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminTokenHandlers groups HTTP handlers for admin token introspection endpoints.
type AdminTokenHandlers struct {
	tokens AdminTokenService
}

// NewAdminTokenHandlers creates a new AdminTokenHandlers with the given AdminTokenService.
func NewAdminTokenHandlers(tokens AdminTokenService) *AdminTokenHandlers {
	return &AdminTokenHandlers{tokens: tokens}
}

// Introspect handles POST /admin/tokens/introspect (RFC 7662).
// For access tokens: decodes the JWT without DB lookup.
// For refresh tokens: performs a DB lookup.
func (h *AdminTokenHandlers) Introspect(c *gin.Context) {
	var req IntrospectRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.tokens.Introspect(c.Request.Context(), req.Token)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
