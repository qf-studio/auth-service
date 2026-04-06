package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminUserHandlers groups HTTP handlers for admin user management endpoints.
type AdminUserHandlers struct {
	users AdminUserService
}

// NewAdminUserHandlers creates a new AdminUserHandlers with the given AdminUserService.
func NewAdminUserHandlers(users AdminUserService) *AdminUserHandlers {
	return &AdminUserHandlers{users: users}
}

// List handles GET /admin/users.
// Query params: page, per_page, status, email, role, created_after, created_before.
// When email, role, or date range filters are provided, delegates to SearchUsers.
func (h *AdminUserHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	status := c.DefaultQuery("status", "")
	email := c.DefaultQuery("email", "")
	role := c.DefaultQuery("role", "")
	createdAfterStr := c.DefaultQuery("created_after", "")
	createdBeforeStr := c.DefaultQuery("created_before", "")

	hasFilters := email != "" || role != "" || createdAfterStr != "" || createdBeforeStr != ""

	if hasFilters {
		var createdAfter, createdBefore *time.Time
		if createdAfterStr != "" {
			t, err := time.Parse(time.RFC3339, createdAfterStr)
			if err != nil {
				domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid created_after: must be RFC3339")
				return
			}
			createdAfter = &t
		}
		if createdBeforeStr != "" {
			t, err := time.Parse(time.RFC3339, createdBeforeStr)
			if err != nil {
				domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid created_before: must be RFC3339")
				return
			}
			createdBefore = &t
		}

		result, err := h.users.SearchUsers(c.Request.Context(), page, perPage, email, role, status, createdAfter, createdBefore)
		if err != nil {
			handleServiceError(c, err)
			return
		}
		c.JSON(http.StatusOK, result)
		return
	}

	result, err := h.users.ListUsers(c.Request.Context(), page, perPage, status)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/users/:id.
func (h *AdminUserHandlers) Get(c *gin.Context) {
	userID := c.Param("id")

	user, err := h.users.GetUser(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// Create handles POST /admin/users.
func (h *AdminUserHandlers) Create(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	user, err := h.users.CreateUser(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, user)
}

// Update handles PATCH /admin/users/:id.
func (h *AdminUserHandlers) Update(c *gin.Context) {
	userID := c.Param("id")

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	user, err := h.users.UpdateUser(c.Request.Context(), userID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// Delete handles DELETE /admin/users/:id (soft delete).
func (h *AdminUserHandlers) Delete(c *gin.Context) {
	userID := c.Param("id")

	if err := h.users.DeleteUser(c.Request.Context(), userID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user deleted"})
}

// Lock handles POST /admin/users/:id/lock.
func (h *AdminUserHandlers) Lock(c *gin.Context) {
	userID := c.Param("id")

	var req LockUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	user, err := h.users.LockUser(c.Request.Context(), userID, req.Reason)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// Unlock handles POST /admin/users/:id/unlock.
func (h *AdminUserHandlers) Unlock(c *gin.Context) {
	userID := c.Param("id")

	user, err := h.users.UnlockUser(c.Request.Context(), userID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, user)
}

// BulkLock handles POST /admin/users/bulk/lock.
func (h *AdminUserHandlers) BulkLock(c *gin.Context) {
	var req BulkUserActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}
	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.users.BulkLock(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// BulkUnlock handles POST /admin/users/bulk/unlock.
func (h *AdminUserHandlers) BulkUnlock(c *gin.Context) {
	var req BulkUserActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}
	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.users.BulkUnlock(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// BulkSuspend handles POST /admin/users/bulk/suspend.
func (h *AdminUserHandlers) BulkSuspend(c *gin.Context) {
	var req BulkUserActionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}
	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.users.BulkSuspend(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// BulkAssignRole handles POST /admin/users/bulk/assign-role.
func (h *AdminUserHandlers) BulkAssignRole(c *gin.Context) {
	var req BulkAssignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}
	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.users.BulkAssignRole(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Activity handles GET /admin/users/:id/activity.
func (h *AdminUserHandlers) Activity(c *gin.Context) {
	userID := c.Param("id")
	page, perPage := parsePagination(c)

	result, err := h.users.GetActivity(c.Request.Context(), userID, page, perPage)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
