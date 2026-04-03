package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/qf-studio/auth-service/internal/domain"
)

// NewPublicRouter creates a *gin.Engine with the full public API route tree.
// Middleware stack order: correlation ID → security headers → rate limit → request size → routes.
func NewPublicRouter(svc *Services, mw *MiddlewareStack) *gin.Engine {
	r := gin.New()
	r.Use(gin.Recovery())

	// Global middleware in specified order.
	// CORS is applied first at engine level so preflight OPTIONS are handled
	// before rate limiting or security checks reject the request.
	if mw != nil {
		if mw.CORS != nil {
			r.Use(mw.CORS)
		}
		if mw.CorrelationID != nil {
			r.Use(mw.CorrelationID)
		}
		if mw.SecurityHeaders != nil {
			r.Use(mw.SecurityHeaders)
		}
		if mw.RateLimit != nil {
			r.Use(mw.RateLimit)
		}
		if mw.RequestSize != nil {
			r.Use(mw.RequestSize)
		}
	}

	v := domain.NewValidator()
	authH := NewAuthHandlers(svc.Auth)
	tokenH := NewTokenHandlers(svc.Token)

	// Health probes (no middleware beyond global).
	r.GET("/health", healthHandler)
	r.GET("/liveness", healthHandler)
	r.GET("/readiness", healthHandler)

	// JWKS endpoint (public, no auth).
	r.GET("/.well-known/jwks.json", tokenH.JWKS)

	// Public auth routes.
	auth := r.Group("/auth")
	{
		auth.POST("/register", validateReq(v, &domain.RegisterRequest{}), authH.Register)
		auth.POST("/login", validateReq(v, &domain.LoginRequest{}), authH.Login)
		auth.POST("/token", validateReq(v, &domain.TokenRequest{}), tokenH.Token)
		auth.POST("/revoke", validateReq(v, &domain.RevokeRequest{}), tokenH.Revoke)

		pw := auth.Group("/password")
		pw.POST("/reset", validateReq(v, &domain.PasswordResetRequest{}), authH.ResetPassword)
		pw.POST("/reset/confirm", validateReq(v, &domain.PasswordResetConfirmRequest{}), authH.ConfirmPasswordReset)
	}

	// Protected auth routes (require auth middleware).
	protected := r.Group("/auth")
	if mw != nil && mw.Auth != nil {
		protected.Use(mw.Auth)
	}
	protected.GET("/me", authH.Me)
	protected.PUT("/me/password", validateReq(v, &domain.PasswordChangeRequest{}), authH.ChangePassword)
	protected.POST("/logout", authH.Logout)
	protected.POST("/logout/all", authH.LogoutAll)

	return r
}

// validateReq creates validation middleware for the given request struct type.
// The zero parameter is used only to capture the type — a fresh instance is created per request.
func validateReq(v *validator.Validate, zero interface{}) gin.HandlerFunc {
	switch zero.(type) {
	case *domain.RegisterRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.RegisterRequest{} })
	case *domain.LoginRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.LoginRequest{} })
	case *domain.TokenRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.TokenRequest{} })
	case *domain.RevokeRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.RevokeRequest{} })
	case *domain.PasswordResetRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.PasswordResetRequest{} })
	case *domain.PasswordResetConfirmRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.PasswordResetConfirmRequest{} })
	case *domain.PasswordChangeRequest:
		return domain.ValidateRequest(v, func() interface{} { return &domain.PasswordChangeRequest{} })
	default:
		panic("unsupported request type for validation middleware")
	}
}

func healthHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
