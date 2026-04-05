package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/metrics"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// adminValidator is the shared validator instance for admin request structs.
var adminValidator = validator.New()

// AdminDeps holds infrastructure dependencies for the admin router.
type AdminDeps struct {
	Health  *health.Service
	Metrics *metrics.Collector
}

// NewAdminRouter creates a *gin.Engine with the admin API route tree.
// Only correlation ID middleware is applied (no auth, no rate limiting).
// The admin port is protected at the network level.
func NewAdminRouter(svc *AdminServices, deps *AdminDeps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.CorrelationID())

	// Health probe with dependency checks.
	hh := newHealthHandlers(deps.Health)
	r.GET("/health", hh.health)

	admin := r.Group("/admin")

	// Metrics endpoints.
	if deps.Metrics != nil {
		admin.GET("/metrics", func(c *gin.Context) {
			c.JSON(http.StatusOK, deps.Metrics.JSONExport())
		})
		admin.GET("/metrics/prometheus", func(c *gin.Context) {
			c.Data(http.StatusOK, "text/plain; charset=utf-8", []byte(deps.Metrics.PrometheusExport()))
		})
	}

	// User management.
	if svc.Users != nil {
		userH := NewAdminUserHandlers(svc.Users)
		users := admin.Group("/users")
		{
			users.GET("", userH.List)
			users.GET("/:id", userH.Get)
			users.POST("", userH.Create)
			users.PATCH("/:id", userH.Update)
			users.DELETE("/:id", userH.Delete)
			users.POST("/:id/lock", userH.Lock)
			users.POST("/:id/unlock", userH.Unlock)
		}
	}

	// Client management.
	if svc.Clients != nil {
		clientH := NewAdminClientHandlers(svc.Clients)
		clients := admin.Group("/clients")
		{
			clients.GET("", clientH.List)
			clients.GET("/:id", clientH.Get)
			clients.POST("", clientH.Create)
			clients.PATCH("/:id", clientH.Update)
			clients.DELETE("/:id", clientH.Delete)
			clients.POST("/:id/rotate-secret", clientH.RotateSecret)
		}
	}

	// Token introspection.
	if svc.Tokens != nil {
		tokenH := NewAdminTokenHandlers(svc.Tokens)
		admin.POST("/tokens/introspect", tokenH.Introspect)
	}

	// RBAC policy and role management.
	if svc.RBAC != nil {
		rbacH := NewAdminRBACHandlers(svc.RBAC)
		rbac := admin.Group("/rbac")
		{
			rbac.GET("/policies", rbacH.ListPolicies)
			rbac.POST("/policies", rbacH.AddPolicy)
			rbac.DELETE("/policies", rbacH.RemovePolicy)
			rbac.GET("/roles/:user_id", rbacH.GetRoles)
			rbac.POST("/roles/:user_id", rbacH.AssignRole)
			rbac.DELETE("/roles/:user_id", rbacH.RemoveRole)
		}
	}

	return r
}

// parsePagination extracts page and per_page query parameters with defaults.
func parsePagination(c *gin.Context) (page, perPage int) {
	page, _ = strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ = strconv.Atoi(c.DefaultQuery("per_page", "20"))

	if page < 1 {
		page = 1
	}
	if perPage < 1 {
		perPage = 20
	}
	if perPage > 100 {
		perPage = 100
	}

	return page, perPage
}

// handleValidationError converts validator errors into domain validation error responses.
func handleValidationError(c *gin.Context, err error) {
	validationErrs, ok := err.(validator.ValidationErrors)
	if !ok {
		domain.RespondWithError(c, http.StatusBadRequest, domain.CodeBadRequest, "validation failed")
		return
	}

	details := make([]domain.ValidationErrorDetail, 0, len(validationErrs))
	for _, fe := range validationErrs {
		details = append(details, domain.ValidationErrorDetail{
			Field:   fe.Field(),
			Message: fe.Tag(),
		})
	}

	domain.RespondWithValidationErrors(c, details)
}
