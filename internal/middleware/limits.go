package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

// RequestSize returns a Gin middleware that rejects requests whose
// Content-Length exceeds the configured maximum body size.
// Requests without Content-Length are allowed through (Gin handles the body read limit).
func RequestSize(cfg config.RequestLimitConfig) gin.HandlerFunc {
	maxBytes := cfg.MaxBodySize

	return func(c *gin.Context) {
		if c.Request.ContentLength > maxBytes {
			domain.RespondWithError(c, http.StatusRequestEntityTooLarge, domain.CodeBadRequest, "request body too large")
			return
		}

		// Also limit the actual read, in case Content-Length is absent or spoofed.
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}

// RequestTimeout returns a Gin middleware that applies a deadline to each request context.
// If the deadline is exceeded, downstream handlers receive a canceled context.
func RequestTimeout(cfg config.RequestLimitConfig) gin.HandlerFunc {
	timeout := cfg.RequestTimeout

	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
		defer cancel()

		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
