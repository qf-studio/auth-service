package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminPasswordPolicyHandlers groups HTTP handlers for admin password policy endpoints.
type AdminPasswordPolicyHandlers struct {
	policies AdminPasswordPolicyService
}

// NewAdminPasswordPolicyHandlers creates a new AdminPasswordPolicyHandlers.
func NewAdminPasswordPolicyHandlers(policies AdminPasswordPolicyService) *AdminPasswordPolicyHandlers {
	return &AdminPasswordPolicyHandlers{policies: policies}
}

// List handles GET /admin/password-policies.
func (h *AdminPasswordPolicyHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)

	result, err := h.policies.ListPolicies(c.Request.Context(), page, perPage)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/password-policies/:id.
func (h *AdminPasswordPolicyHandlers) Get(c *gin.Context) {
	policyID := c.Param("id")

	policy, err := h.policies.GetPolicy(c.Request.Context(), policyID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Create handles POST /admin/password-policies.
func (h *AdminPasswordPolicyHandlers) Create(c *gin.Context) {
	var req CreatePasswordPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	policy, err := h.policies.CreatePolicy(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, policy)
}

// Update handles PUT /admin/password-policies/:id.
func (h *AdminPasswordPolicyHandlers) Update(c *gin.Context) {
	policyID := c.Param("id")

	var req UpdatePasswordPolicyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	policy, err := h.policies.UpdatePolicy(c.Request.Context(), policyID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, policy)
}

// Delete handles DELETE /admin/password-policies/:id.
func (h *AdminPasswordPolicyHandlers) Delete(c *gin.Context) {
	policyID := c.Param("id")

	if err := h.policies.DeletePolicy(c.Request.Context(), policyID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password policy deleted"})
}

// Compliance handles GET /admin/password-policies/compliance.
func (h *AdminPasswordPolicyHandlers) Compliance(c *gin.Context) {
	report, err := h.policies.ComplianceReport(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, report)
}
