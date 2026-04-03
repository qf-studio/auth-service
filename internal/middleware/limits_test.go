package middleware_test

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/middleware"
)

func TestRequestSize_AllowsSmallBody(t *testing.T) {
	cfg := config.RequestLimitConfig{
		MaxBodySize:    1024, // 1 KiB
		RequestTimeout: 30 * time.Second,
	}

	r := gin.New()
	r.Use(middleware.RequestSize(cfg))
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	body := bytes.NewBufferString(`{"key": "value"}`)
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", body)
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestSize_RejectsLargeBody(t *testing.T) {
	cfg := config.RequestLimitConfig{
		MaxBodySize:    100, // 100 bytes
		RequestTimeout: 30 * time.Second,
	}

	r := gin.New()
	r.Use(middleware.RequestSize(cfg))
	r.POST("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	// Create a body larger than 100 bytes.
	largeBody := bytes.NewBufferString(strings.Repeat("x", 200))
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/test", largeBody)
	req.Header.Set("Content-Type", "application/json")
	req.ContentLength = 200
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)
}

func TestRequestSize_AllowsGETWithNoBody(t *testing.T) {
	cfg := config.RequestLimitConfig{
		MaxBodySize:    100,
		RequestTimeout: 30 * time.Second,
	}

	r := gin.New()
	r.Use(middleware.RequestSize(cfg))
	r.GET("/test", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestTimeout_SetsDeadline(t *testing.T) {
	cfg := config.RequestLimitConfig{
		MaxBodySize:    1024,
		RequestTimeout: 5 * time.Second,
	}

	r := gin.New()
	r.Use(middleware.RequestTimeout(cfg))
	r.GET("/test", func(c *gin.Context) {
		deadline, ok := c.Request.Context().Deadline()
		require.True(t, ok, "context should have a deadline")
		assert.WithinDuration(t, time.Now().Add(5*time.Second), deadline, 1*time.Second)
		c.String(http.StatusOK, "ok")
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestRequestTimeout_ShortTimeout(t *testing.T) {
	cfg := config.RequestLimitConfig{
		MaxBodySize:    1024,
		RequestTimeout: 1 * time.Millisecond,
	}

	r := gin.New()
	r.Use(middleware.RequestTimeout(cfg))
	r.GET("/test", func(c *gin.Context) {
		// Wait a bit to allow timeout to kick in.
		time.Sleep(10 * time.Millisecond)

		select {
		case <-c.Request.Context().Done():
			c.String(http.StatusGatewayTimeout, "timeout")
		default:
			c.String(http.StatusOK, "ok")
		}
	})

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
	r.ServeHTTP(w, req)

	// The handler should detect the canceled context.
	assert.Equal(t, http.StatusGatewayTimeout, w.Code)
}
