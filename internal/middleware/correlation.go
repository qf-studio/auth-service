package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const correlationIDHeader = "X-Request-ID"

// contextKeyLogger is the Gin context key for the per-request logger.
const contextKeyLogger = "logger"

// CorrelationID returns a Gin middleware that ensures every request has a
// unique X-Request-ID header. If the incoming request already carries the
// header, its value is preserved; otherwise a new UUID v4 is generated.
// The ID is also set on the response so callers can correlate logs.
//
// When a base logger is provided, the middleware creates a child logger with
// the request_id field and stores it in the Gin context under "logger".
func CorrelationID(baseLogger ...*zap.Logger) gin.HandlerFunc {
	var base *zap.Logger
	if len(baseLogger) > 0 {
		base = baseLogger[0]
	}

	return func(c *gin.Context) {
		id := c.GetHeader(correlationIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		c.Set("request_id", id)
		c.Header(correlationIDHeader, id)

		if base != nil {
			reqLogger := base.With(zap.String("request_id", id))
			c.Set(contextKeyLogger, reqLogger)
		}

		c.Next()
	}
}

// LoggerFromContext retrieves the per-request logger from the Gin context.
// Returns nil if no logger was set (i.e., CorrelationID was called without a base logger).
func LoggerFromContext(c *gin.Context) *zap.Logger {
	if l, exists := c.Get(contextKeyLogger); exists {
		if zl, ok := l.(*zap.Logger); ok {
			return zl
		}
	}
	return nil
}
