package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const correlationIDHeader = "X-Request-ID"

// CorrelationID returns a Gin middleware that ensures every request has a
// unique X-Request-ID header. If the incoming request already carries the
// header, its value is preserved; otherwise a new UUID v4 is generated.
// The ID is also set on the response so callers can correlate logs.
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(correlationIDHeader)
		if id == "" {
			id = uuid.NewString()
		}
		c.Set("request_id", id)
		c.Header(correlationIDHeader, id)
		c.Next()
	}
}
