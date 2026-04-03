package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminClientHandlers groups HTTP handlers for admin client management endpoints.
type AdminClientHandlers struct {
	clients AdminClientService
}

// NewAdminClientHandlers creates a new AdminClientHandlers with the given AdminClientService.
func NewAdminClientHandlers(clients AdminClientService) *AdminClientHandlers {
	return &AdminClientHandlers{clients: clients}
}

// List handles GET /admin/clients.
// Query params: page (default 1), per_page (default 20), client_type (service|agent), include_revoked (default false).
func (h *AdminClientHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	clientType := c.DefaultQuery("client_type", "")
	includeRevoked, _ := strconv.ParseBool(c.DefaultQuery("include_revoked", "false"))

	result, err := h.clients.ListClients(c.Request.Context(), page, perPage, clientType, includeRevoked)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/clients/:id.
func (h *AdminClientHandlers) Get(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clients.GetClient(c.Request.Context(), clientID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, client)
}

// Create handles POST /admin/clients.
// Returns the client with the generated secret (only time secret is visible).
func (h *AdminClientHandlers) Create(c *gin.Context) {
	var req CreateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	client, err := h.clients.CreateClient(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, client)
}

// Update handles PATCH /admin/clients/:id.
func (h *AdminClientHandlers) Update(c *gin.Context) {
	clientID := c.Param("id")

	var req UpdateClientRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	client, err := h.clients.UpdateClient(c.Request.Context(), clientID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, client)
}

// Delete handles DELETE /admin/clients/:id (soft delete).
func (h *AdminClientHandlers) Delete(c *gin.Context) {
	clientID := c.Param("id")

	if err := h.clients.DeleteClient(c.Request.Context(), clientID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "client deleted"})
}

// RotateSecret handles POST /admin/clients/:id/rotate-secret.
// Returns the new secret with a 24-hour grace period for the old secret.
func (h *AdminClientHandlers) RotateSecret(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.clients.RotateSecret(c.Request.Context(), clientID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, client)
}
