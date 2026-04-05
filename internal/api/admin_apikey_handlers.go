package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminAPIKeyHandlers groups HTTP handlers for admin API key management endpoints.
type AdminAPIKeyHandlers struct {
	apiKeys AdminAPIKeyService
}

// NewAdminAPIKeyHandlers creates a new AdminAPIKeyHandlers with the given AdminAPIKeyService.
func NewAdminAPIKeyHandlers(apiKeys AdminAPIKeyService) *AdminAPIKeyHandlers {
	return &AdminAPIKeyHandlers{apiKeys: apiKeys}
}

// List handles GET /admin/apikeys.
// Query params: page (default 1), per_page (default 20), client_id (filter by client).
func (h *AdminAPIKeyHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	clientID := c.DefaultQuery("client_id", "")

	result, err := h.apiKeys.ListAPIKeys(c.Request.Context(), page, perPage, clientID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/apikeys/:id.
func (h *AdminAPIKeyHandlers) Get(c *gin.Context) {
	keyID := c.Param("id")

	key, err := h.apiKeys.GetAPIKey(c.Request.Context(), keyID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, key)
}

// Create handles POST /admin/apikeys.
// Returns the API key with the generated raw key (only time key is visible).
func (h *AdminAPIKeyHandlers) Create(c *gin.Context) {
	var req CreateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	key, err := h.apiKeys.CreateAPIKey(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, key)
}

// Update handles PATCH /admin/apikeys/:id.
func (h *AdminAPIKeyHandlers) Update(c *gin.Context) {
	keyID := c.Param("id")

	var req UpdateAPIKeyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	key, err := h.apiKeys.UpdateAPIKey(c.Request.Context(), keyID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, key)
}

// Delete handles DELETE /admin/apikeys/:id (revoke).
func (h *AdminAPIKeyHandlers) Delete(c *gin.Context) {
	keyID := c.Param("id")

	if err := h.apiKeys.RevokeAPIKey(c.Request.Context(), keyID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "api key revoked"})
}

// Rotate handles POST /admin/apikeys/:id/rotate.
// Returns the new key with a 24-hour grace period for the old key.
func (h *AdminAPIKeyHandlers) Rotate(c *gin.Context) {
	keyID := c.Param("id")

	key, err := h.apiKeys.RotateAPIKey(c.Request.Context(), keyID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, key)
}
