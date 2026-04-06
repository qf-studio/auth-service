package api

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminWebhookHandlers groups HTTP handlers for admin webhook management endpoints.
type AdminWebhookHandlers struct {
	webhooks AdminWebhookService
}

// NewAdminWebhookHandlers creates a new AdminWebhookHandlers with the given AdminWebhookService.
func NewAdminWebhookHandlers(webhooks AdminWebhookService) *AdminWebhookHandlers {
	return &AdminWebhookHandlers{webhooks: webhooks}
}

// List handles GET /admin/webhooks.
// Query params: page (default 1), per_page (default 20), active (filter active only).
func (h *AdminWebhookHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)
	activeOnly := c.DefaultQuery("active", "") == "true"

	result, err := h.webhooks.ListWebhooks(c.Request.Context(), page, perPage, activeOnly)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// Get handles GET /admin/webhooks/:id.
func (h *AdminWebhookHandlers) Get(c *gin.Context) {
	webhookID := c.Param("id")

	wh, err := h.webhooks.GetWebhook(c.Request.Context(), webhookID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, wh)
}

// Create handles POST /admin/webhooks.
// Returns the webhook with the generated signing secret (only time secret is visible).
func (h *AdminWebhookHandlers) Create(c *gin.Context) {
	var req CreateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	wh, err := h.webhooks.CreateWebhook(c.Request.Context(), &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusCreated, wh)
}

// Update handles PATCH /admin/webhooks/:id.
func (h *AdminWebhookHandlers) Update(c *gin.Context) {
	webhookID := c.Param("id")

	var req UpdateWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	wh, err := h.webhooks.UpdateWebhook(c.Request.Context(), webhookID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, wh)
}

// Delete handles DELETE /admin/webhooks/:id.
func (h *AdminWebhookHandlers) Delete(c *gin.Context) {
	webhookID := c.Param("id")

	if err := h.webhooks.DeleteWebhook(c.Request.Context(), webhookID); err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "webhook deleted"})
}

// ListDeliveries handles GET /admin/webhooks/:id/deliveries.
func (h *AdminWebhookHandlers) ListDeliveries(c *gin.Context) {
	webhookID := c.Param("id")
	page, perPage := parsePagination(c)

	result, err := h.webhooks.ListDeliveries(c.Request.Context(), webhookID, page, perPage)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}

// RetryDelivery handles POST /admin/webhooks/:id/deliveries/:delivery_id/retry.
func (h *AdminWebhookHandlers) RetryDelivery(c *gin.Context) {
	webhookID := c.Param("id")
	deliveryID := c.Param("delivery_id")

	delivery, err := h.webhooks.RetryDelivery(c.Request.Context(), webhookID, deliveryID)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, delivery)
}

// Test handles POST /admin/webhooks/:id/test.
func (h *AdminWebhookHandlers) Test(c *gin.Context) {
	webhookID := c.Param("id")

	var req TestWebhookRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid request body")
		return
	}

	if err := adminValidator.Struct(req); err != nil {
		handleValidationError(c, err)
		return
	}

	result, err := h.webhooks.TestWebhook(c.Request.Context(), webhookID, &req)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
