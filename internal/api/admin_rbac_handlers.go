package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminRBACHandlers groups HTTP handlers for admin RBAC policy and role endpoints.
type AdminRBACHandlers struct {
	rbac AdminRBACService
}

// NewAdminRBACHandlers creates a new AdminRBACHandlers with the given AdminRBACService.
func NewAdminRBACHandlers(rbac AdminRBACService) *AdminRBACHandlers {
	return &AdminRBACHandlers{rbac: rbac}
}

// ListPolicies handles GET /admin/rbac/policies.
func (h *AdminRBACHandlers) ListPolicies(c *gin.Context) {
	result, err := h.rbac.ListPolicies(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// CreatePolicy handles POST /admin/rbac/policies.
func (h *AdminRBACHandlers) CreatePolicy(c *gin.Context) {
	var req CreatePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	policy, err := h.rbac.CreatePolicy(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// DeletePolicy handles DELETE /admin/rbac/policies.
// The policy to remove is specified in the request body.
func (h *AdminRBACHandlers) DeletePolicy(c *gin.Context) {
	var req DeletePolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	if err := h.rbac.DeletePolicy(c.Request.Context(), &req); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "policy deleted"})
}

// GetUserRoles handles GET /admin/rbac/roles/:user.
func (h *AdminRBACHandlers) GetUserRoles(c *gin.Context) {
	user := c.Param("user")

	result, err := h.rbac.GetUserRoles(c.Request.Context(), user)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// AssignRole handles POST /admin/rbac/roles.
func (h *AdminRBACHandlers) AssignRole(c *gin.Context) {
	var req AssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.rbac.AssignRole(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, result)
}
