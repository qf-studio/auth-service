package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
)

// --- Mock AdminTokenService ---

type mockAdminTokenService struct {
	introspectFn func(ctx context.Context, token string) (*api.IntrospectionResponse, error)
}

func (m *mockAdminTokenService) Introspect(ctx context.Context, token string) (*api.IntrospectionResponse, error) {
	if m.introspectFn != nil {
		return m.introspectFn(ctx, token)
	}
	return &api.IntrospectionResponse{
		Active:     true,
		Sub:        "user-42",
		TokenType:  "access_token",
		Scope:      "read:users write:users",
		Exp:        1700000000,
		Iat:        1699996400,
		Iss:        "auth-service",
		Jti:        "token-id-1",
		ClientType: "user",
	}, nil
}

// --- Helper ---

func newAdminTokenRouter(tokenSvc api.AdminTokenService) *gin.Engine {
	svc := &api.AdminServices{Tokens: tokenSvc}
	return api.NewAdminRouter(svc)
}

// --- Introspect ---

func TestAdminIntrospect_ActiveToken(t *testing.T) {
	r := newAdminTokenRouter(&mockAdminTokenService{})
	body := map[string]string{"token": "qf_at_valid_access_token"}
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Active)
	assert.Equal(t, "user-42", resp.Sub)
	assert.Equal(t, "access_token", resp.TokenType)
	assert.Equal(t, "read:users write:users", resp.Scope)
	assert.Equal(t, "auth-service", resp.Iss)
	assert.Equal(t, "token-id-1", resp.Jti)
}

func TestAdminIntrospect_InactiveToken(t *testing.T) {
	svc := &mockAdminTokenService{
		introspectFn: func(_ context.Context, _ string) (*api.IntrospectionResponse, error) {
			return &api.IntrospectionResponse{Active: false}, nil
		},
	}
	r := newAdminTokenRouter(svc)
	body := map[string]string{"token": "qf_at_expired_token"}
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.False(t, resp.Active)
	assert.Empty(t, resp.Sub, "inactive tokens should not expose claims")
}

func TestAdminIntrospect_RefreshToken(t *testing.T) {
	svc := &mockAdminTokenService{
		introspectFn: func(_ context.Context, token string) (*api.IntrospectionResponse, error) {
			assert.Equal(t, "qf_rt_refresh_token", token)
			return &api.IntrospectionResponse{
				Active:    true,
				Sub:       "user-99",
				TokenType: "refresh_token",
				Exp:       1700100000,
				Iat:       1699996400,
				Jti:       "rt-id-1",
			}, nil
		},
	}
	r := newAdminTokenRouter(svc)
	body := map[string]string{"token": "qf_rt_refresh_token"}
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.IntrospectionResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Active)
	assert.Equal(t, "refresh_token", resp.TokenType)
}

func TestAdminIntrospect_MissingToken(t *testing.T) {
	r := newAdminTokenRouter(&mockAdminTokenService{})
	body := map[string]string{}
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminIntrospect_InvalidJSON(t *testing.T) {
	r := newAdminTokenRouter(&mockAdminTokenService{})
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminIntrospect_ServiceError(t *testing.T) {
	svc := &mockAdminTokenService{
		introspectFn: func(_ context.Context, _ string) (*api.IntrospectionResponse, error) {
			return nil, fmt.Errorf("decode failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminTokenRouter(svc)
	body := map[string]string{"token": "qf_at_malformed"}
	w := doRequest(r, http.MethodPost, "/admin/tokens/introspect", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Nil services don't crash ---

func TestAdminRouter_NilServices(t *testing.T) {
	svc := &api.AdminServices{}
	router := api.NewAdminRouter(svc)

	// Health should still work.
	w := doRequest(router, http.MethodGet, "/health", nil)
	assert.Equal(t, http.StatusOK, w.Code)

	// Routes for nil services should 404 (not registered).
	w = doRequest(router, http.MethodGet, "/admin/users", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = doRequest(router, http.MethodGet, "/admin/clients", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)

	w = doRequest(router, http.MethodPost, "/admin/tokens/introspect", map[string]string{"token": "x"})
	assert.Equal(t, http.StatusNotFound, w.Code)
}
