package docs_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/docs"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestPublicSpec(t *testing.T) {
	r := gin.New()
	r.GET("/docs/openapi.json", docs.PublicSpec())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.json", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var spec map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &spec)
	require.NoError(t, err, "response must be valid JSON")

	// Verify it's the public spec.
	info, ok := spec["info"].(map[string]interface{})
	require.True(t, ok, "spec must have info object")
	assert.Contains(t, info["title"], "Public")
}

func TestAdminSpec(t *testing.T) {
	r := gin.New()
	r.GET("/admin/docs/openapi.json", docs.AdminSpec())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/admin/docs/openapi.json", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "application/json; charset=utf-8", w.Header().Get("Content-Type"))

	var spec map[string]interface{}
	err := json.Unmarshal(w.Body.Bytes(), &spec)
	require.NoError(t, err, "response must be valid JSON")

	info, ok := spec["info"].(map[string]interface{})
	require.True(t, ok, "spec must have info object")
	assert.Contains(t, info["title"], "Admin")
}

func TestPublicSpecContent(t *testing.T) {
	r := gin.New()
	r.GET("/docs/openapi.json", docs.PublicSpec())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs/openapi.json", http.NoBody)
	r.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var spec map[string]interface{}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &spec))

	// Check OpenAPI version. yaml.v3 unmarshals unquoted "3.1.0" as float64.
	assert.Contains(t, []interface{}{"3.1.0", 3.1}, spec["openapi"])

	// Check paths exist.
	paths, ok := spec["paths"].(map[string]interface{})
	require.True(t, ok, "spec must have paths")
	assert.Contains(t, paths, "/auth/register")
	assert.Contains(t, paths, "/auth/login")
	assert.Contains(t, paths, "/.well-known/jwks.json")
}

func TestRedocHTML(t *testing.T) {
	r := gin.New()
	r.GET("/docs", docs.RedocHTML("/docs/openapi.json"))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/docs", http.NoBody)
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "text/html; charset=utf-8", w.Header().Get("Content-Type"))

	body := w.Body.String()
	assert.True(t, strings.Contains(body, "redoc"), "page must include redoc")
	assert.True(t, strings.Contains(body, "/docs/openapi.json"), "page must reference spec URL")
}

func TestRegisterPublicRoutes(t *testing.T) {
	r := gin.New()
	docs.RegisterPublicRoutes(r)

	tests := []struct {
		name string
		path string
	}{
		{"spec endpoint", "/docs/openapi.json"},
		{"redoc UI", "/docs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestRegisterAdminRoutes(t *testing.T) {
	r := gin.New()
	docs.RegisterAdminRoutes(r)

	tests := []struct {
		name string
		path string
	}{
		{"spec endpoint", "/admin/docs/openapi.json"},
		{"redoc UI", "/admin/docs"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, tt.path, http.NoBody)
			r.ServeHTTP(w, req)
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestSpecsAreConsistentJSON(t *testing.T) {
	// Both specs should produce identical results on repeated calls (cached).
	r := gin.New()
	docs.RegisterPublicRoutes(r)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/docs/openapi.json", http.NoBody))

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/docs/openapi.json", http.NoBody))

	assert.Equal(t, w1.Body.String(), w2.Body.String(), "repeated requests must return identical content")
}
