package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/middleware"
)

func TestCorrelationID_GeneratesIDWhenMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.CorrelationID())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	respID := w.Header().Get("X-Request-ID")
	assert.NotEmpty(t, respID, "should generate an X-Request-ID when none provided")
	assert.Len(t, respID, 36, "generated ID should be a UUID")
}

func TestCorrelationID_PreservesExistingID(t *testing.T) {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(middleware.CorrelationID())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"id": c.GetString("request_id")})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "existing-id-123")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "existing-id-123", w.Header().Get("X-Request-ID"))
}
