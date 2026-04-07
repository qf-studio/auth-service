package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
)

// NewPublicRouter creates a *gin.Engine with the full public API route tree.
// Middleware stack order: correlation ID → security headers → rate limit → request size → metrics → routes.
func NewPublicRouter(svc *Services, mw *MiddlewareStack, healthSvc *health.Service) *gin.Engine {
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
		if mw.Metrics != nil {
			r.Use(mw.Metrics)
		}
		if mw.Tenant != nil {
			r.Use(mw.Tenant)
		}
	}

	v := domain.NewValidator()
	authH := NewAuthHandlers(svc.Auth, svc.Session)
	tokenH := NewTokenHandlers(svc.Token, svc.DPoP)

	var sessionH *SessionHandlers
	if svc.Session != nil {
		sessionH = NewSessionHandlers(svc.Session)
	}

	var mfaH *MFAHandlers
	if svc.MFA != nil {
		mfaH = NewMFAHandlers(svc.MFA)
	}

	var oauthH *OAuthHandlers
	if svc.OAuth != nil {
		oauthH = NewOAuthHandlers(svc.OAuth)
	}

	var oidcH *OIDCHandlers
	if svc.OIDC != nil {
		oidcH = NewOIDCHandlers(svc.OIDC)
	}

	// Health probes (no middleware beyond global).
	hh := newHealthHandlers(healthSvc)
	r.GET("/health", hh.health)
	r.GET("/liveness", hh.liveness)
	r.GET("/readiness", hh.readiness)

	// JWKS endpoint (public, no auth).
	r.GET("/.well-known/jwks.json", tokenH.JWKS)

	// OIDC discovery and authorization endpoints (public, no auth).
	if oidcH != nil {
		r.GET("/.well-known/openid-configuration", oidcH.Discovery)
		r.GET("/oauth/authorize", oidcH.Authorize)
		r.POST("/oauth/token", oidcH.Token)
	}

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

		// Broker token issuance (public, authenticates via client credentials in body).
		if svc.Broker != nil {
			brokerH := NewBrokerHandlers(svc.Broker)
			auth.POST("/broker/token", brokerH.Token)
		}

		// MFA verify is public (uses mfa_token, not bearer auth).
		if mfaH != nil {
			auth.POST("/mfa/verify", mfaH.Verify)
		}

		// OAuth initiation and callback are public (no auth required).
		if oauthH != nil {
			auth.GET("/oauth/:provider", oauthH.Redirect)
			auth.GET("/oauth/:provider/callback", oauthH.Callback)
		}

		// SAML SSO endpoints (public, no auth required).
		if svc.SAML != nil {
			samlH := NewSAMLHandlers(svc.SAML)
			auth.GET("/saml/metadata", samlH.Metadata)
			auth.GET("/saml/login", samlH.Login)
			auth.POST("/saml/acs", samlH.ACS)
		}
	}

	// Protected auth routes (require API key or auth middleware).
	protected := r.Group("/auth")
	if mw != nil && mw.APIKey != nil {
		protected.Use(mw.APIKey)
	}
	if mw != nil && mw.Auth != nil {
		protected.Use(mw.Auth)
	}
	if mw != nil && mw.DPoP != nil {
		protected.Use(mw.DPoP)
	}
	protected.GET("/me", authH.Me)
	protected.PUT("/me/password", validateReq(v, &domain.PasswordChangeRequest{}), authH.ChangePassword)
	protected.POST("/logout", authH.Logout)
	protected.POST("/logout/all", authH.LogoutAll)

	if sessionH != nil {
		protected.GET("/sessions", sessionH.List)
		protected.DELETE("/sessions/:id", sessionH.Delete)
		protected.DELETE("/sessions", sessionH.DeleteAll)
	}

	if mfaH != nil {
		mfa := protected.Group("/mfa")
		mfa.POST("/setup", mfaH.Setup)
		mfa.POST("/confirm", mfaH.Confirm)
		mfa.POST("/disable", mfaH.Disable)
		mfa.GET("/status", mfaH.Status)
	}

	if oauthH != nil {
		protected.GET("/me/oauth", oauthH.ListLinked)
		protected.DELETE("/me/oauth/:provider", oauthH.Unlink)
	}

	// OIDC UserInfo endpoint (requires auth, at root path per OIDC spec).
	if oidcH != nil {
		userinfo := r.Group("")
		if mw != nil && mw.APIKey != nil {
			userinfo.Use(mw.APIKey)
		}
		if mw != nil && mw.Auth != nil {
			userinfo.Use(mw.Auth)
		}
		userinfo.GET("/userinfo", oidcH.UserInfo)
	}

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

// healthHandlers wraps a health.Service to provide HTTP handler methods.
type healthHandlers struct {
	svc *health.Service
}

func newHealthHandlers(svc *health.Service) *healthHandlers {
	return &healthHandlers{svc: svc}
}

func (h *healthHandlers) health(c *gin.Context) {
	resp := h.svc.Health(c.Request.Context())
	status := http.StatusOK
	if resp.Status == health.StatusUnhealthy {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, resp.ToMarshalable())
}

func (h *healthHandlers) liveness(c *gin.Context) {
	resp := h.svc.Liveness()
	c.JSON(http.StatusOK, resp.ToMarshalable())
}

func (h *healthHandlers) readiness(c *gin.Context) {
	resp := h.svc.Readiness(c.Request.Context())
	status := http.StatusOK
	if resp.Status != health.StatusHealthy {
		status = http.StatusServiceUnavailable
	}
	c.JSON(status, resp.ToMarshalable())
}
