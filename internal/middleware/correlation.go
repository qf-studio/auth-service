package middleware

import (
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CorrelationIDHeader is the HTTP header used to propagate correlation IDs.
const CorrelationIDHeader = "X-Request-ID"

// CorrelationIDKey is the Gin context key where the correlation ID is stored.
const CorrelationIDKey = "correlation_id"

// CorrelationID returns Gin middleware that reads X-Request-ID from the incoming
// request or generates a new UUID v4 if absent. The ID is stored in the Gin
// context and set on the response header.
func CorrelationID() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.GetHeader(CorrelationIDHeader)
		if id == "" {
			id = uuid.New().String()
		}
		c.Set(CorrelationIDKey, id)
		c.Header(CorrelationIDHeader, id)
		c.Next()
	}
}
