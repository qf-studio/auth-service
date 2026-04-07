package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminTenantHandlers groups HTTP handlers for admin tenant management endpoints.
type AdminTenantHandlers struct {
	tenants AdminTenantService
}

// NewAdminTenantHandlers creates a new AdminTenantHandlers.
func NewAdminTenantHandlers(tenants AdminTenantService) *AdminTenantHandlers {
	return &AdminTenantHandlers{tenants: tenants}
}

// List handles GET /admin/tenants.
// Query params: page (default 1), per_page (default 20), status (optional).
func (h *AdminTenantHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	status := c.DefaultQuery("status", "")

	result, err := h.tenants.ListTenants(c.Request.Context(), page, perPage, status)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/tenants/:id.
func (h *AdminTenantHandlers) Get(c *gin.Context) {
	tenantID := c.Param("id")

	tenant, err := h.tenants.GetTenant(c.Request.Context(), tenantID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// Create handles POST /admin/tenants.
func (h *AdminTenantHandlers) Create(c *gin.Context) {
	var req CreateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	tenant, err := h.tenants.CreateTenant(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, tenant)
}

// Update handles PATCH /admin/tenants/:id.
func (h *AdminTenantHandlers) Update(c *gin.Context) {
	tenantID := c.Param("id")

	var req UpdateTenantRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	tenant, err := h.tenants.UpdateTenant(c.Request.Context(), tenantID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, tenant)
}

// Delete handles DELETE /admin/tenants/:id (soft delete).
func (h *AdminTenantHandlers) Delete(c *gin.Context) {
	tenantID := c.Param("id")

	if err := h.tenants.DeleteTenant(c.Request.Context(), tenantID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "tenant deleted"})
}
