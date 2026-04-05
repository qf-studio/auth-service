package middleware

import (
	"context"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	apiKeyHeader       = "X-API-Key"
	clientIDContextKey = "client_id"
	scopesContextKey   = "scopes"
)

// APIKeyValidator defines the operations required by APIKeyMiddleware
// to validate an API key and retrieve its associated metadata.
type APIKeyValidator interface {
	ValidateAPIKey(ctx context.Context, rawKey string) (*APIKeyInfo, error)
}

// APIKeyInfo contains the validated API key metadata set into the request context.
type APIKeyInfo struct {
	ClientID  string
	Scopes    []string
	RateLimit int
}

// APIKeyMiddleware returns a Gin middleware that authenticates requests via
// the X-API-Key header. If no X-API-Key header is present, the middleware
// falls through (calls c.Next()) so the existing Bearer token auth middleware
// can handle authentication. If the header is present but invalid, the
// middleware returns 401.
//
// On success it sets "claims" (synthesized *domain.TokenClaims), "client_id",
// "scopes", and rate limit headers into the context.
func APIKeyMiddleware(validator APIKeyValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		raw := c.GetHeader(apiKeyHeader)
		if raw == "" {
			// No API key header — fall through to Bearer token auth.
			c.Next()
			return
		}

		info, err := validator.ValidateAPIKey(c.Request.Context(), raw)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid or expired API key")
			return
		}

		// Set claims-compatible context so downstream handlers work uniformly.
		claims := &domain.TokenClaims{
			Subject:    info.ClientID,
			Scopes:     info.Scopes,
			ClientType: domain.ClientTypeService,
		}
		c.Set(claimsContextKey, claims)
		c.Set(clientIDContextKey, info.ClientID)
		c.Set(scopesContextKey, info.Scopes)

		// Set rate limit headers for downstream consumption.
		c.Header("X-RateLimit-Limit", strconv.Itoa(info.RateLimit))

		c.Next()
	}
}
