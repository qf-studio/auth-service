package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminBrokerHandlers groups HTTP handlers for admin broker credential management endpoints.
type AdminBrokerHandlers struct {
	brokers AdminBrokerService
}

// NewAdminBrokerHandlers creates a new AdminBrokerHandlers with the given AdminBrokerService.
func NewAdminBrokerHandlers(brokers AdminBrokerService) *AdminBrokerHandlers {
	return &AdminBrokerHandlers{brokers: brokers}
}

// List handles GET /admin/credentials.
// Query params: page (default 1), per_page (default 20), owner_client_id (filter by owner).
func (h *AdminBrokerHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	ownerClientID := c.DefaultQuery("owner_client_id", "")

	result, err := h.brokers.ListCredentials(c.Request.Context(), page, perPage, ownerClientID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/credentials/:id.
func (h *AdminBrokerHandlers) Get(c *gin.Context) {
	credentialID := c.Param("id")

	cred, err := h.brokers.GetCredential(c.Request.Context(), credentialID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, cred)
}

// Create handles POST /admin/credentials.
// Returns the credential with the generated secret (only time secret is visible).
func (h *AdminBrokerHandlers) Create(c *gin.Context) {
	var req CreateBrokerCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	cred, err := h.brokers.CreateCredential(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, cred)
}

// Update handles PATCH /admin/credentials/:id.
func (h *AdminBrokerHandlers) Update(c *gin.Context) {
	credentialID := c.Param("id")

	var req UpdateBrokerCredentialRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	cred, err := h.brokers.UpdateCredential(c.Request.Context(), credentialID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, cred)
}

// Delete handles DELETE /admin/credentials/:id.
func (h *AdminBrokerHandlers) Delete(c *gin.Context) {
	credentialID := c.Param("id")

	if err := h.brokers.DeleteCredential(c.Request.Context(), credentialID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "credential deleted"})
}

// Rotate handles POST /admin/credentials/:id/rotate.
// Returns the credential with the new secret and a grace period for the old one.
func (h *AdminBrokerHandlers) Rotate(c *gin.Context) {
	credentialID := c.Param("id")

	cred, err := h.brokers.RotateCredential(c.Request.Context(), credentialID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, cred)
}
