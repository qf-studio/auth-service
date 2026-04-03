package api

import (
	"net/http"
	"strconv"

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
// Query params: page (default 1), per_page (default 20), include_deleted (default false).
func (h *AdminUserHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	includeDeleted, _ := strconv.ParseBool(c.DefaultQuery("include_deleted", "false"))

	result, err := h.users.ListUsers(c.Request.Context(), page, perPage, includeDeleted)
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
