package api

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminDashboardHandlers groups HTTP handlers for admin dashboard endpoints.
type AdminDashboardHandlers struct {
	dashboard AdminDashboardService
}

// NewAdminDashboardHandlers creates a new AdminDashboardHandlers.
func NewAdminDashboardHandlers(dashboard AdminDashboardService) *AdminDashboardHandlers {
	return &AdminDashboardHandlers{dashboard: dashboard}
}

// Overview handles GET /admin/dashboard/overview.
func (h *AdminDashboardHandlers) Overview(c *gin.Context) {
	result, err := h.dashboard.Overview(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// Security handles GET /admin/dashboard/security.
func (h *AdminDashboardHandlers) Security(c *gin.Context) {
	result, err := h.dashboard.Security(c.Request.Context())
	if err != nil {
		handleServiceError(c, err)
		return
	}
	c.JSON(http.StatusOK, result)
}

// ListAuditLogs handles GET /admin/audit-logs.
// Query params: page, per_page, action, user_id, severity, start_date, end_date.
func (h *AdminDashboardHandlers) ListAuditLogs(c *gin.Context) {
	page, perPage := parsePagination(c)

	action := c.DefaultQuery("action", "")
	actorID := c.DefaultQuery("user_id", "")
	severity := c.DefaultQuery("severity", "")

	var startDate, endDate *time.Time

	if sd := c.DefaultQuery("start_date", ""); sd != "" {
		t, err := time.Parse(time.RFC3339, sd)
		if err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest,
				"invalid start_date: expected RFC3339 format")
			return
		}
		startDate = &t
	}

	if ed := c.DefaultQuery("end_date", ""); ed != "" {
		t, err := time.Parse(time.RFC3339, ed)
		if err != nil {
			domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest,
				"invalid end_date: expected RFC3339 format")
			return
		}
		endDate = &t
	}

	result, err := h.dashboard.ListAuditLogs(c.Request.Context(), page, perPage,
		action, actorID, severity, startDate, endDate)
	if err != nil {
		handleServiceError(c, err)
		return
	}

	c.JSON(http.StatusOK, result)
}
