package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminSAMLHandlers groups HTTP handlers for admin SAML IdP management endpoints.
type AdminSAMLHandlers struct {
	saml AdminSAMLService
}

// NewAdminSAMLHandlers creates a new AdminSAMLHandlers with the given AdminSAMLService.
func NewAdminSAMLHandlers(saml AdminSAMLService) *AdminSAMLHandlers {
	return &AdminSAMLHandlers{saml: saml}
}

// List handles GET /admin/saml/idps.
// Query params: page (default 1), per_page (default 20).
func (h *AdminSAMLHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)

	result, err := h.saml.ListIdPs(c.Request.Context(), page, perPage)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/saml/idps/:id.
func (h *AdminSAMLHandlers) Get(c *gin.Context) {
	idpID := c.Param("id")

	idp, err := h.saml.GetIdP(c.Request.Context(), idpID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, idp)
}

// Create handles POST /admin/saml/idps.
func (h *AdminSAMLHandlers) Create(c *gin.Context) {
	var req CreateSAMLIdPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	idp, err := h.saml.CreateIdP(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, idp)
}

// Update handles PATCH /admin/saml/idps/:id.
func (h *AdminSAMLHandlers) Update(c *gin.Context) {
	idpID := c.Param("id")

	var req UpdateSAMLIdPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	idp, err := h.saml.UpdateIdP(c.Request.Context(), idpID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, idp)
}

// Delete handles DELETE /admin/saml/idps/:id.
func (h *AdminSAMLHandlers) Delete(c *gin.Context) {
	idpID := c.Param("id")

	if err := h.saml.DeleteIdP(c.Request.Context(), idpID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "IdP configuration deleted"})
}

// ImportMetadata handles POST /admin/saml/idps/:id/metadata.
// Imports IdP metadata XML to configure the IdP.
func (h *AdminSAMLHandlers) ImportMetadata(c *gin.Context) {
	idpID := c.Param("id")

	var req ImportSAMLMetadataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	idp, err := h.saml.ImportMetadata(c.Request.Context(), idpID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, idp)
}

// ExportMetadata handles GET /admin/saml/idps/:id/metadata.
// Returns the IdP metadata XML.
func (h *AdminSAMLHandlers) ExportMetadata(c *gin.Context) {
	idpID := c.Param("id")

	xmlData, err := h.saml.ExportMetadata(c.Request.Context(), idpID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.Data(http.StatusOK, "application/xml", xmlData)
}

// UpdateAttributeMapping handles PUT /admin/saml/idps/:id/attribute-mapping.
// Configures how SAML attributes map to internal user fields.
func (h *AdminSAMLHandlers) UpdateAttributeMapping(c *gin.Context) {
	idpID := c.Param("id")

	var req SAMLAttributeMappingRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	idp, err := h.saml.UpdateAttributeMapping(c.Request.Context(), idpID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, idp)
}

// GetAttributeMapping handles GET /admin/saml/idps/:id/attribute-mapping.
// Returns the current attribute mapping configuration.
func (h *AdminSAMLHandlers) GetAttributeMapping(c *gin.Context) {
	idpID := c.Param("id")

	mapping, err := h.saml.GetAttributeMapping(c.Request.Context(), idpID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"attribute_mapping": mapping})
}
