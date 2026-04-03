package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func init() { gin.SetMode(gin.TestMode) }

func TestCorrelationID(t *testing.T) {
	tests := []struct {
		name       string
		headerVal  string
		wantCustom bool
	}{
		{
			name:       "generates UUID when header missing",
			headerVal:  "",
			wantCustom: false,
		},
		{
			name:       "propagates existing header",
			headerVal:  "req-abc-123",
			wantCustom: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := gin.New()
			r.Use(CorrelationID())

			var ctxID string
			r.GET("/test", func(c *gin.Context) {
				v, _ := c.Get(CorrelationIDKey)
				ctxID, _ = v.(string)
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			if tt.headerVal != "" {
				req.Header.Set(CorrelationIDHeader, tt.headerVal)
			}
			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			respID := w.Header().Get(CorrelationIDHeader)
			require.NotEmpty(t, respID, "response must have X-Request-ID")
			assert.Equal(t, ctxID, respID, "context value must match response header")

			if tt.wantCustom {
				assert.Equal(t, tt.headerVal, respID, "should propagate provided ID")
			} else {
				assert.Len(t, respID, 36, "generated UUID should be 36 chars (8-4-4-4-12)")
			}
		})
	}
}

func TestCorrelationID_UniquePerRequest(t *testing.T) {
	r := gin.New()
	r.Use(CorrelationID())
	r.GET("/test", func(c *gin.Context) { c.Status(http.StatusOK) })

	ids := make(map[string]bool, 50)
	for i := 0; i < 50; i++ {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)

		id := w.Header().Get(CorrelationIDHeader)
		require.NotEmpty(t, id)
		assert.False(t, ids[id], "duplicate correlation ID at iteration %d", i)
		ids[id] = true
	}
}
