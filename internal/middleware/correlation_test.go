package middleware_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

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

func TestCorrelationID_InjectsLoggerWithRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	core, logs := observer.New(zap.InfoLevel)
	baseLogger := zap.New(core)

	r := gin.New()
	r.Use(middleware.CorrelationID(baseLogger))

	var capturedLogger *zap.Logger
	r.GET("/test", func(c *gin.Context) {
		capturedLogger = middleware.LoggerFromContext(c)
		if capturedLogger != nil {
			capturedLogger.Info("test log")
		}
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	req.Header.Set("X-Request-ID", "test-req-456")
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.NotNil(t, capturedLogger, "logger should be set in context")
	require.Equal(t, 1, logs.Len(), "should have one log entry")

	entry := logs.All()[0]
	assert.Equal(t, "test log", entry.Message)

	// Verify request_id field is present on the logger.
	found := false
	for _, f := range entry.Context {
		if f.Key == "request_id" && f.String == "test-req-456" {
			found = true
			break
		}
	}
	assert.True(t, found, "log entry should contain request_id field")
}

func TestCorrelationID_NoLoggerWithoutBase(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CorrelationID())

	var capturedLogger *zap.Logger
	r.GET("/test", func(c *gin.Context) {
		capturedLogger = middleware.LoggerFromContext(c)
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Nil(t, capturedLogger, "logger should be nil when no base logger provided")
}

func TestCorrelationID_ResponseHeaderSetWithGeneratedID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CorrelationID())
	r.GET("/test", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	respID := w.Header().Get("X-Request-ID")
	assert.NotEmpty(t, respID, "response should have X-Request-ID header")
	assert.Len(t, respID, 36, "generated ID should be a UUID")
}

func TestCorrelationID_ContextHasRequestID(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.Use(middleware.CorrelationID())

	var ctxID string
	r.GET("/test", func(c *gin.Context) {
		ctxID = c.GetString("request_id")
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, ctxID, "request_id should be set in context")
	assert.Equal(t, ctxID, w.Header().Get("X-Request-ID"), "context and header IDs should match")
}
