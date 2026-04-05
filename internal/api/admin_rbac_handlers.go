package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminRBACHandlers handles admin RBAC policy and role-assignment endpoints.
type AdminRBACHandlers struct {
	svc AdminRBACService
}

// NewAdminRBACHandlers creates a new AdminRBACHandlers.
func NewAdminRBACHandlers(svc AdminRBACService) *AdminRBACHandlers {
	return &AdminRBACHandlers{svc: svc}
}

// ListPolicies handles GET /admin/rbac/policies
// Returns all Casbin policy rules.
func (h *AdminRBACHandlers) ListPolicies(c *gin.Context) {
	policies, err := h.svc.ListPolicies(c.Request.Context())
	if err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to list policies")
		return
	}
	c.JSON(http.StatusOK, gin.H{"policies": policies})
}

// AddPolicy handles POST /admin/rbac/policies
// Body: {"sub": "...", "obj": "...", "act": "..."}
func (h *AdminRBACHandlers) AddPolicy(c *gin.Context) {
	var req AdminRBACPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	if err := h.svc.AddPolicy(c.Request.Context(), req.Subject, req.Object, req.Action); err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to add policy")
		return
	}
	c.Status(http.StatusNoContent)
}

// RemovePolicy handles DELETE /admin/rbac/policies
// Body: {"sub": "...", "obj": "...", "act": "..."}
func (h *AdminRBACHandlers) RemovePolicy(c *gin.Context) {
	var req AdminRBACPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	if err := h.svc.RemovePolicy(c.Request.Context(), req.Subject, req.Object, req.Action); err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to remove policy")
		return
	}
	c.Status(http.StatusNoContent)
}

// GetRoles handles GET /admin/rbac/roles/:user_id
// Returns all Casbin roles assigned to the given user.
func (h *AdminRBACHandlers) GetRoles(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "user_id is required")
		return
	}

	roles, err := h.svc.GetRolesForUser(c.Request.Context(), userID)
	if err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to get roles")
		return
	}
	c.JSON(http.StatusOK, gin.H{"user_id": userID, "roles": roles})
}

// AssignRole handles POST /admin/rbac/roles/:user_id
// Body: {"role": "..."}
func (h *AdminRBACHandlers) AssignRole(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "user_id is required")
		return
	}

	var req AdminRBACRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	if err := h.svc.AssignRole(c.Request.Context(), userID, req.Role); err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to assign role")
		return
	}
	c.Status(http.StatusNoContent)
}

// RemoveRole handles DELETE /admin/rbac/roles/:user_id
// Body: {"role": "..."}
func (h *AdminRBACHandlers) RemoveRole(c *gin.Context) {
	userID := c.Param("user_id")
	if userID == "" {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "user_id is required")
		return
	}

	var req AdminRBACRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	if err := h.svc.RemoveRole(c.Request.Context(), userID, req.Role); err != nil {
		domain.RespondWithError(c, http.StatusInternalServerError, domain.CodeInternalError,
			"failed to remove role")
		return
	}
	c.Status(http.StatusNoContent)
}
