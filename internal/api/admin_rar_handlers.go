package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminRARHandlers groups HTTP handlers for admin RAR type management endpoints.
type AdminRARHandlers struct {
	rar AdminRARService
}

// NewAdminRARHandlers creates a new AdminRARHandlers with the given AdminRARService.
func NewAdminRARHandlers(rar AdminRARService) *AdminRARHandlers {
	return &AdminRARHandlers{rar: rar}
}

// List handles GET /admin/rar/types.
// Query params: page (default 1), per_page (default 20).
func (h *AdminRARHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)

	result, err := h.rar.ListRARTypes(c.Request.Context(), page, perPage)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/rar/types/:type.
func (h *AdminRARHandlers) Get(c *gin.Context) {
	rarType := c.Param("type")

	rt, err := h.rar.GetRARType(c.Request.Context(), rarType)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, rt)
}

// Create handles POST /admin/rar/types.
func (h *AdminRARHandlers) Create(c *gin.Context) {
	var req CreateRARTypeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	rt, err := h.rar.CreateRARType(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, rt)
}

// Update handles PATCH /admin/rar/types/:type.
func (h *AdminRARHandlers) Update(c *gin.Context) {
	rarType := c.Param("type")

	var req UpdateRARTypeRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	rt, err := h.rar.UpdateRARType(c.Request.Context(), rarType, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, rt)
}

// Delete handles DELETE /admin/rar/types/:type.
func (h *AdminRARHandlers) Delete(c *gin.Context) {
	rarType := c.Param("type")

	if err := h.rar.DeleteRARType(c.Request.Context(), rarType); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "authorization type deleted"})
}
