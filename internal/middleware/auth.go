package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Context keys used by auth and RBAC middleware.
const (
	claimsContextKey  = "claims"
	userIDContextKey  = "user_id"
	accessTokenPrefix = "qf_at_"
)

// TokenValidator defines the token operations required by AuthMiddleware.
// token.Service implements this interface.
type TokenValidator interface {
	// ValidateToken parses and cryptographically validates the raw token
	// (with the qf_at_ prefix already stripped), returning its claims.
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)

	// IsRevoked reports whether the token identified by tokenID has been
	// revoked (i.e., is present in the Redis blocklist).
	IsRevoked(ctx context.Context, tokenID string) (bool, error)
}

// AuthMiddleware returns a Gin middleware that authenticates requests via
// Bearer tokens. It:
//
//  1. Extracts the token from Authorization: Bearer <token>
//  2. Verifies the qf_at_ prefix
//  3. Validates the token via TokenValidator
//  4. Checks the Redis revocation blocklist
//  5. Stores *domain.TokenClaims under "claims" and the subject under "user_id"
//
// Returns 401 on any authentication failure.
func AuthMiddleware(validator TokenValidator) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip if already authenticated (e.g., by APIKeyMiddleware).
		if _, exists := c.Get(claimsContextKey); exists {
			c.Next()
			return
		}

		raw := extractBearer(c)
		if raw == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"missing or malformed Authorization header")
			return
		}

		if !strings.HasPrefix(raw, accessTokenPrefix) {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid token format")
			return
		}
		token := strings.TrimPrefix(raw, accessTokenPrefix)

		claims, err := validator.ValidateToken(c.Request.Context(), token)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid or expired token")
			return
		}

		revoked, err := validator.IsRevoked(c.Request.Context(), claims.TokenID)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"token validation failed")
			return
		}
		if revoked {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"token has been revoked")
			return
		}

		c.Set(claimsContextKey, claims)
		c.Set(userIDContextKey, claims.Subject)
		c.Next()
	}
}

// extractBearer pulls the token value from the Authorization header.
// Returns an empty string if the header is absent or not in Bearer format.
func extractBearer(c *gin.Context) string {
	auth := c.GetHeader("Authorization")
	if len(auth) > 7 && auth[:7] == "Bearer " {
		return auth[7:]
	}
	return ""
}
