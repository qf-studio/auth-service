package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/middleware"
)

const testAdminTokenOld = "test-not-a-real-old-admin-token-0000"

func newAuthAdminRouter(t *testing.T, tokens []string, maxBody int64) *gin.Engine {
	t.Helper()
	deps := &api.AdminDeps{
		Health:      health.NewService(),
		APITokens:   tokens,
		RequestSize: middleware.RequestSize(config.RequestLimitConfig{MaxBodySize: maxBody}),
	}
	svc := &api.AdminServices{Consent: &mockConsentService{}, ClientApproval: &mockClientApprovalService{}}
	return mustRouter(api.NewAdminRouter(svc, deps))
}

func adminReq(r *gin.Engine, method, path, authz, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	return w
}

func TestAdminRouter_BearerToken(t *testing.T) {
	r := newAuthAdminRouter(t, []string{testAdminToken, testAdminTokenOld}, 1024)

	tests := []struct {
		name   string
		authz  string
		status int
	}{
		{"no header", "", http.StatusUnauthorized},
		{"wrong token", "Bearer wrong-wrong-wrong-wrong-wrong-wrong", http.StatusUnauthorized},
		{"wrong scheme", "Basic " + testAdminToken, http.StatusUnauthorized},
		{"prefix of valid token", "Bearer " + testAdminToken[:10], http.StatusUnauthorized},
		{"first token", "Bearer " + testAdminToken, http.StatusOK},
		{"second token", "Bearer " + testAdminTokenOld, http.StatusOK},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			w := adminReq(r, http.MethodPost, "/admin/clients/c1/approve", tc.authz, "")
			assert.Equal(t, tc.status, w.Code)
			if tc.status == http.StatusUnauthorized {
				var resp domain.ErrorResponse
				require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
				assert.Equal(t, domain.CodeUnauthorized, resp.Code)
			}
		})
	}
}

func TestAdminRouter_HealthUnauthenticated(t *testing.T) {
	for name, tokens := range map[string][]string{"configured": {testAdminToken}, "unconfigured": nil} {
		t.Run(name, func(t *testing.T) {
			r := newAuthAdminRouter(t, tokens, 1024)
			w := adminReq(r, http.MethodGet, "/health", "", "")
			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

func TestAdminRouter_NoTokensConfigured_Returns503(t *testing.T) {
	r := newAuthAdminRouter(t, nil, 1024)

	for _, authz := range []string{"", "Bearer " + testAdminToken} {
		w := adminReq(r, http.MethodPost, "/admin/clients/c1/approve", authz, "")
		require.Equal(t, http.StatusServiceUnavailable, w.Code)
		var resp domain.ErrorResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "admin_api_disabled", resp.Code)
	}
}

func TestAdminRouter_NoTokensConfigured_UsersRoute503(t *testing.T) {
	svc := &api.AdminServices{Users: &mockAdminUserService{}}
	r := mustRouter(api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()}))

	w := adminReq(r, http.MethodGet, "/admin/users", "", "")
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAdminRouter_RequestSizeLimit(t *testing.T) {
	r := newAuthAdminRouter(t, []string{testAdminToken}, 16)

	w := adminReq(r, http.MethodPost, "/admin/clients/c1/approve", "Bearer "+testAdminToken, strings.Repeat("x", 64))
	assert.Equal(t, http.StatusRequestEntityTooLarge, w.Code)

	w = adminReq(r, http.MethodPost, "/admin/clients/c1/approve", "Bearer "+testAdminToken, "{}")
	assert.Equal(t, http.StatusOK, w.Code)
}
