package middleware

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/config"
)

// CORS returns a Gin middleware that handles Cross-Origin Resource Sharing.
// It uses the provided CORSConfig to determine allowed origins, methods, headers,
// and other CORS parameters. Preflight OPTIONS requests are handled and terminated.
func CORS(cfg config.CORSConfig) gin.HandlerFunc {
	allowedOrigins := make(map[string]struct{}, len(cfg.AllowedOrigins))
	for _, o := range cfg.AllowedOrigins {
		allowedOrigins[o] = struct{}{}
	}

	allowWildcard := false
	if _, ok := allowedOrigins["*"]; ok {
		allowWildcard = true
	}

	methods := strings.Join(cfg.AllowedMethods, ", ")
	headers := strings.Join(cfg.AllowedHeaders, ", ")
	exposed := strings.Join(cfg.ExposeHeaders, ", ")
	maxAge := strconv.Itoa(int(cfg.MaxAge.Seconds()))

	return func(c *gin.Context) {
		origin := c.GetHeader("Origin")
		if origin == "" {
			c.Next()
			return
		}

		// Check if origin is allowed.
		allowed := allowWildcard
		if !allowed {
			_, allowed = allowedOrigins[origin]
		}
		if !allowed {
			c.Next()
			return
		}

		h := c.Writer.Header()
		h.Set("Access-Control-Allow-Origin", origin)
		h.Set("Vary", "Origin")

		if cfg.AllowCredentials {
			h.Set("Access-Control-Allow-Credentials", "true")
		}

		if exposed != "" {
			h.Set("Access-Control-Expose-Headers", exposed)
		}

		// Handle preflight.
		if c.Request.Method == http.MethodOptions {
			h.Set("Access-Control-Allow-Methods", methods)
			h.Set("Access-Control-Allow-Headers", headers)
			h.Set("Access-Control-Max-Age", maxAge)
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	}
}
