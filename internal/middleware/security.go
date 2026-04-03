package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders returns a Gin middleware that sets standard security headers
// on every response per OWASP and NIST recommendations.
//
// Headers set:
//   - X-Content-Type-Options: nosniff
//   - X-Frame-Options: DENY
//   - X-XSS-Protection: 0  (modern browsers use CSP)
//   - Content-Security-Policy: default-src 'none'
//   - Strict-Transport-Security: max-age=31536000; includeSubDomains
//   - Referrer-Policy: strict-origin-when-cross-origin
//   - Cache-Control: no-store  (auth responses must not be cached)
//   - Permissions-Policy: (empty — deny all browser features)
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		h := c.Writer.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-XSS-Protection", "0")
		h.Set("Content-Security-Policy", "default-src 'none'")
		h.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		h.Set("Cache-Control", "no-store")
		h.Set("Permissions-Policy", "")
		c.Next()
	}
}
