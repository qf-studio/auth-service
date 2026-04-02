// Package docs embeds OpenAPI specifications from api/ and provides Gin handlers
// for serving them as JSON. Specs are converted from YAML to JSON at init time.
//
// After modifying specs in api/, run: go generate ./internal/docs/
package docs

//go:generate sh -c "cp ../../api/*.yaml specs/"

import (
	"embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"

	"github.com/gin-gonic/gin"
	"gopkg.in/yaml.v3"
)

//go:embed specs/*.yaml
var specsFS embed.FS

var (
	publicJSON []byte
	adminJSON  []byte
	initOnce   sync.Once
	initErr    error
)

// initSpecs converts embedded YAML specs to JSON exactly once.
func initSpecs() {
	initOnce.Do(func() {
		publicJSON, initErr = yamlFileToJSON("specs/public.openapi.yaml")
		if initErr != nil {
			initErr = fmt.Errorf("public spec: %w", initErr)
			return
		}
		adminJSON, initErr = yamlFileToJSON("specs/admin.openapi.yaml")
		if initErr != nil {
			initErr = fmt.Errorf("admin spec: %w", initErr)
		}
	})
}

func yamlFileToJSON(path string) ([]byte, error) {
	raw, err := specsFS.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}

	var doc interface{}
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}

	// yaml.v3 produces map[string]interface{} by default, which encoding/json handles fine.
	j, err := json.Marshal(doc)
	if err != nil {
		return nil, fmt.Errorf("marshal %s: %w", path, err)
	}
	return j, nil
}

// PublicSpec returns the Gin handler for GET /docs/openapi.json.
func PublicSpec() gin.HandlerFunc {
	initSpecs()
	return func(c *gin.Context) {
		if initErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "spec unavailable"})
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", publicJSON)
	}
}

// AdminSpec returns the Gin handler for GET /admin/docs/openapi.json.
func AdminSpec() gin.HandlerFunc {
	initSpecs()
	return func(c *gin.Context) {
		if initErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "spec unavailable"})
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", adminJSON)
	}
}

// RedocHTML returns a Gin handler that serves a Redoc UI page pointing at the given spec URL.
func RedocHTML(specURL string) gin.HandlerFunc {
	page := fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
  <title>Auth Service — API Docs</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <style>body { margin: 0; padding: 0; }</style>
</head>
<body>
  <redoc spec-url='%s'></redoc>
  <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
</body>
</html>`, specURL)

	return func(c *gin.Context) {
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(page))
	}
}

// RegisterPublicRoutes adds documentation routes to a public Gin router.
func RegisterPublicRoutes(r *gin.Engine) {
	r.GET("/docs/openapi.json", PublicSpec())
	r.GET("/docs", RedocHTML("/docs/openapi.json"))
}

// RegisterAdminRoutes adds documentation routes to an admin Gin router.
func RegisterAdminRoutes(r *gin.Engine) {
	r.GET("/admin/docs/openapi.json", AdminSpec())
	r.GET("/admin/docs", RedocHTML("/admin/docs/openapi.json"))
}
