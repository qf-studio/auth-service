package middleware

import (
	"crypto/subtle"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AdminToken returns a Gin middleware that requires an
// "Authorization: Bearer <token>" header matching one of the configured admin
// API tokens (ADMIN_API_TOKENS). Several tokens may be accepted at once so a
// credential can be rotated without downtime.
//
// With no tokens configured every request is rejected with 503
// admin_api_disabled, so the admin API fails closed while the rest of the
// service keeps running. A missing or wrong credential yields 401.
func AdminToken(tokens []string) gin.HandlerFunc {
	accepted := make([][]byte, 0, len(tokens))
	for _, t := range tokens {
		if t != "" {
			accepted = append(accepted, []byte(t))
		}
	}

	return func(c *gin.Context) {
		if len(accepted) == 0 {
			domain.RespondWithError(c, http.StatusServiceUnavailable, domain.CodeAdminAPIDisabled,
				"admin API is disabled: no admin API tokens are configured")
			return
		}

		raw := extractBearer(c)
		if raw == "" {
			c.Header("WWW-Authenticate", "Bearer")
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"missing or malformed Authorization header")
			return
		}

		// Compare against every token without short-circuiting so timing does
		// not reveal which configured token (if any) matched.
		presented := []byte(raw)
		match := 0
		for _, tok := range accepted {
			match |= subtle.ConstantTimeCompare(presented, tok)
		}
		if match != 1 {
			c.Header("WWW-Authenticate", `Bearer error="invalid_token"`)
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid admin credential")
			return
		}

		c.Next()
	}
}
