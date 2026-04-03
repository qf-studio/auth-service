package middleware

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// ErrNoClaims is returned by GetClaims when AuthMiddleware has not run or
// claims are absent from the Gin context.
var ErrNoClaims = errors.New("no token claims in context")

// GetClaims retrieves the *domain.TokenClaims stored by AuthMiddleware.
// Returns ErrNoClaims if the claims key is absent or has the wrong type.
func GetClaims(c *gin.Context) (*domain.TokenClaims, error) {
	raw, exists := c.Get(claimsContextKey)
	if !exists {
		return nil, ErrNoClaims
	}
	claims, ok := raw.(*domain.TokenClaims)
	if !ok {
		return nil, ErrNoClaims
	}
	return claims, nil
}

// RequireRoles returns a Gin middleware that enforces role-based access control.
// Access is granted if the token's roles contain ANY of the specified roles
// (any-of semantics). Returns 403 Forbidden if no role matches.
// Returns 401 Unauthorized if AuthMiddleware has not populated claims.
func RequireRoles(roles ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"authentication required")
			return
		}

		for _, required := range roles {
			for _, held := range claims.Roles {
				if held == required {
					c.Next()
					return
				}
			}
		}

		domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden,
			"insufficient role")
	}
}

// RequireScopes returns a Gin middleware that enforces scope-based access control.
// Access is granted only if the token's scopes contain ALL of the specified
// scopes (all-of semantics). Returns 403 Forbidden if any scope is missing.
// Returns 401 Unauthorized if AuthMiddleware has not populated claims.
func RequireScopes(scopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"authentication required")
			return
		}

		held := make(map[string]struct{}, len(claims.Scopes))
		for _, s := range claims.Scopes {
			held[s] = struct{}{}
		}

		for _, required := range scopes {
			if _, ok := held[required]; !ok {
				domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden,
					"insufficient scope")
				return
			}
		}

		c.Next()
	}
}

// RequireClientType returns a Gin middleware that restricts access to
// specific client types. Access is granted if the token's ClientType matches
// ANY of the specified types (any-of semantics). Returns 403 Forbidden if the
// client type does not match.
// Returns 401 Unauthorized if AuthMiddleware has not populated claims.
func RequireClientType(types ...domain.ClientType) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"authentication required")
			return
		}

		for _, t := range types {
			if claims.ClientType == t {
				c.Next()
				return
			}
		}

		domain.RespondWithError(c, http.StatusForbidden, domain.CodeForbidden,
			"client type not permitted")
	}
}
