package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminAuditHandlers provides HTTP handlers for the admin audit log API.
type AdminAuditHandlers struct {
	audit AdminAuditService
}

// NewAdminAuditHandlers creates a new AdminAuditHandlers.
func NewAdminAuditHandlers(audit AdminAuditService) *AdminAuditHandlers {
	return &AdminAuditHandlers{audit: audit}
}

// List handles GET /admin/audit with pagination and filters.
// Query parameters:
//   - page, per_page: pagination (defaults: 1, 20)
//   - user_id: filter by user ID
//   - client_id: filter by client ID
//   - event_type: filter by event type
//   - start_date: filter events on or after this RFC 3339 timestamp
//   - end_date: filter events on or before this RFC 3339 timestamp
func (h *AdminAuditHandlers) List(c *gin.Context) {
	page, perPage := parsePagination(c)

	filter := AuditFilter{
		UserID:    c.Query("user_id"),
		ClientID:  c.Query("client_id"),
		EventType: c.Query("event_type"),
	}

	if raw := c.Query("start_date"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid start_date: expected RFC 3339 format")
			return
		}
		filter.StartDate = &t
	}

	if raw := c.Query("end_date"); raw != "" {
		t, err := time.Parse(time.RFC3339, raw)
		if err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "invalid end_date: expected RFC 3339 format")
			return
		}
		filter.EndDate = &t
	}

	result, err := h.audit.ListEvents(c.Request.Context(), page, perPage, filter)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
