package api

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// adminValidator is the shared validator instance for admin request structs.
var adminValidator = validator.New()

// NewAdminRouter creates a *gin.Engine with the admin API route tree.
// Only correlation ID middleware is applied (no auth, no rate limiting).
// The admin port is protected at the network level.
func NewAdminRouter(svc *AdminServices) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())
	r.Use(middleware.CorrelationID())

	// Health probe.
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	admin := r.Group("/admin")

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
