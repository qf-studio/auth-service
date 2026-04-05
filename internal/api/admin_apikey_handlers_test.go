package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminAPIKeyService ---

type mockAdminAPIKeyService struct {
	listAPIKeysFn  func(ctx context.Context, page, perPage int, clientID string) (*api.AdminAPIKeyList, error)
	getAPIKeyFn    func(ctx context.Context, keyID string) (*api.AdminAPIKey, error)
	createAPIKeyFn func(ctx context.Context, req *api.CreateAPIKeyRequest) (*api.AdminAPIKeyWithSecret, error)
	updateAPIKeyFn func(ctx context.Context, keyID string, req *api.UpdateAPIKeyRequest) (*api.AdminAPIKey, error)
	revokeAPIKeyFn func(ctx context.Context, keyID string) error
	rotateAPIKeyFn func(ctx context.Context, keyID string) (*api.AdminAPIKeyWithSecret, error)
}

func (m *mockAdminAPIKeyService) ListAPIKeys(ctx context.Context, page, perPage int, clientID string) (*api.AdminAPIKeyList, error) {
	if m.listAPIKeysFn != nil {
		return m.listAPIKeysFn(ctx, page, perPage, clientID)
	}
	return &api.AdminAPIKeyList{
		APIKeys: []api.AdminAPIKey{{
			ID:        "ak1",
			ClientID:  "c1",
			Name:      "test-key",
			KeyPrefix: "qf_ak_abcd1234",
			Scopes:    []string{"read:users"},
			RateLimit: 1000,
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminAPIKeyService) GetAPIKey(ctx context.Context, keyID string) (*api.AdminAPIKey, error) {
	if m.getAPIKeyFn != nil {
		return m.getAPIKeyFn(ctx, keyID)
	}
	return &api.AdminAPIKey{
		ID:        keyID,
		ClientID:  "c1",
		Name:      "test-key",
		KeyPrefix: "qf_ak_abcd1234",
		Scopes:    []string{"read:users"},
		RateLimit: 1000,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (m *mockAdminAPIKeyService) CreateAPIKey(ctx context.Context, req *api.CreateAPIKeyRequest) (*api.AdminAPIKeyWithSecret, error) {
	if m.createAPIKeyFn != nil {
		return m.createAPIKeyFn(ctx, req)
	}
	return &api.AdminAPIKeyWithSecret{
		AdminAPIKey: api.AdminAPIKey{
			ID:        "new-key",
			ClientID:  req.ClientID,
			Name:      req.Name,
			KeyPrefix: "qf_ak_abcd1234",
			Scopes:    req.Scopes,
			RateLimit: 1000,
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Key: "qf_ak_abcdef0123456789abcdef0123456789",
	}, nil
}

func (m *mockAdminAPIKeyService) UpdateAPIKey(ctx context.Context, keyID string, req *api.UpdateAPIKeyRequest) (*api.AdminAPIKey, error) {
	if m.updateAPIKeyFn != nil {
		return m.updateAPIKeyFn(ctx, keyID, req)
	}
	name := "test-key"
	if req.Name != nil {
		name = *req.Name
	}
	rateLimit := 1000
	if req.RateLimit != nil {
		rateLimit = *req.RateLimit
	}
	return &api.AdminAPIKey{
		ID:        keyID,
		ClientID:  "c1",
		Name:      name,
		KeyPrefix: "qf_ak_abcd1234",
		Scopes:    req.Scopes,
		RateLimit: rateLimit,
		Status:    "active",
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}, nil
}

func (m *mockAdminAPIKeyService) RevokeAPIKey(ctx context.Context, keyID string) error {
	if m.revokeAPIKeyFn != nil {
		return m.revokeAPIKeyFn(ctx, keyID)
	}
	return nil
}

func (m *mockAdminAPIKeyService) RotateAPIKey(ctx context.Context, keyID string) (*api.AdminAPIKeyWithSecret, error) {
	if m.rotateAPIKeyFn != nil {
		return m.rotateAPIKeyFn(ctx, keyID)
	}
	graceEnd := time.Now().Add(24 * time.Hour)
	return &api.AdminAPIKeyWithSecret{
		AdminAPIKey: api.AdminAPIKey{
			ID:        keyID,
			ClientID:  "c1",
			Name:      "test-key",
			KeyPrefix: "qf_ak_abcd1234",
			Scopes:    []string{"read:users"},
			RateLimit: 1000,
			Status:    "active",
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		},
		Key:             "qf_ak_new_rotated_key_value_here",
		GracePeriodEnds: &graceEnd,
	}, nil
}

// --- Helper ---

func newAdminAPIKeyRouter(apiKeySvc api.AdminAPIKeyService) *gin.Engine {
	svc := &api.AdminServices{APIKeys: apiKeySvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List API Keys ---

func TestAdminListAPIKeys_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodGet, "/admin/apikeys", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAPIKeyList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.APIKeys, 1)
}

func TestAdminListAPIKeys_Pagination(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		listAPIKeysFn: func(_ context.Context, page, perPage int, clientID string) (*api.AdminAPIKeyList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "", clientID)
			return &api.AdminAPIKeyList{APIKeys: []api.AdminAPIKey{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/apikeys?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAPIKeyList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListAPIKeys_FilterByClient(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		listAPIKeysFn: func(_ context.Context, page, perPage int, clientID string) (*api.AdminAPIKeyList, error) {
			assert.Equal(t, "client-123", clientID)
			return &api.AdminAPIKeyList{APIKeys: []api.AdminAPIKey{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/apikeys?client_id=client-123", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListAPIKeys_PerPageCapped(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		listAPIKeysFn: func(_ context.Context, page, perPage int, _ string) (*api.AdminAPIKeyList, error) {
			assert.Equal(t, 1, page)
			assert.Equal(t, 100, perPage) // Capped at 100
			return &api.AdminAPIKeyList{APIKeys: []api.AdminAPIKey{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/apikeys?per_page=999", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Get API Key ---

func TestAdminGetAPIKey_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodGet, "/admin/apikeys/key-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAPIKey
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "key-1", resp.ID)
}

func TestAdminGetAPIKey_NotFound(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		getAPIKeyFn: func(_ context.Context, _ string) (*api.AdminAPIKey, error) {
			return nil, fmt.Errorf("api key not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/apikeys/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create API Key ---

func TestAdminCreateAPIKey_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	body := map[string]interface{}{
		"client_id": "550e8400-e29b-41d4-a716-446655440000",
		"name":      "my-api-key",
		"scopes":    []string{"read:users", "write:users"},
	}
	w := doRequest(r, http.MethodPost, "/admin/apikeys", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminAPIKeyWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-api-key", resp.Name)
	assert.NotEmpty(t, resp.Key, "key must be returned on create")
}

func TestAdminCreateAPIKey_MissingName(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	body := map[string]interface{}{
		"client_id": "550e8400-e29b-41d4-a716-446655440000",
	}
	w := doRequest(r, http.MethodPost, "/admin/apikeys", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateAPIKey_MissingClientID(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	body := map[string]interface{}{
		"name": "my-key",
	}
	w := doRequest(r, http.MethodPost, "/admin/apikeys", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateAPIKey_InvalidJSON(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodPost, "/admin/apikeys", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateAPIKey_InvalidClientID(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	body := map[string]interface{}{
		"client_id": "not-a-uuid",
		"name":      "my-key",
	}
	w := doRequest(r, http.MethodPost, "/admin/apikeys", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateAPIKey_ServiceError(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		createAPIKeyFn: func(_ context.Context, _ *api.CreateAPIKeyRequest) (*api.AdminAPIKeyWithSecret, error) {
			return nil, fmt.Errorf("create failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	body := map[string]interface{}{
		"client_id": "550e8400-e29b-41d4-a716-446655440000",
		"name":      "my-key",
	}
	w := doRequest(r, http.MethodPost, "/admin/apikeys", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Update API Key ---

func TestAdminUpdateAPIKey_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	name := "updated-key"
	body := map[string]interface{}{"name": name}
	w := doRequest(r, http.MethodPatch, "/admin/apikeys/key-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAPIKey
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "updated-key", resp.Name)
}

func TestAdminUpdateAPIKey_NotFound(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		updateAPIKeyFn: func(_ context.Context, _ string, _ *api.UpdateAPIKeyRequest) (*api.AdminAPIKey, error) {
			return nil, fmt.Errorf("api key not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	body := map[string]interface{}{"name": "nope"}
	w := doRequest(r, http.MethodPatch, "/admin/apikeys/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdateAPIKey_InvalidJSON(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodPatch, "/admin/apikeys/key-1", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUpdateAPIKey_WithRateLimit(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		updateAPIKeyFn: func(_ context.Context, keyID string, req *api.UpdateAPIKeyRequest) (*api.AdminAPIKey, error) {
			assert.Equal(t, "key-1", keyID)
			require.NotNil(t, req.RateLimit)
			assert.Equal(t, 500, *req.RateLimit)
			return &api.AdminAPIKey{
				ID:        keyID,
				ClientID:  "c1",
				Name:      "test-key",
				KeyPrefix: "qf_ak_abcd1234",
				Scopes:    []string{},
				RateLimit: 500,
				Status:    "active",
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}, nil
		},
	}
	r := newAdminAPIKeyRouter(svc)
	body := map[string]interface{}{"rate_limit": 500}
	w := doRequest(r, http.MethodPatch, "/admin/apikeys/key-1", body)

	assert.Equal(t, http.StatusOK, w.Code)
}

// --- Delete (Revoke) API Key ---

func TestAdminDeleteAPIKey_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodDelete, "/admin/apikeys/key-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteAPIKey_NotFound(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		revokeAPIKeyFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("api key not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/apikeys/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminDeleteAPIKey_AlreadyRevoked(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		revokeAPIKeyFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("api key already revoked: %w", api.ErrConflict)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/apikeys/revoked-key", nil)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Rotate API Key ---

func TestAdminRotateAPIKey_Success(t *testing.T) {
	r := newAdminAPIKeyRouter(&mockAdminAPIKeyService{})
	w := doRequest(r, http.MethodPost, "/admin/apikeys/key-1/rotate", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminAPIKeyWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Key, "new key must be returned on rotation")
	assert.NotNil(t, resp.GracePeriodEnds, "grace period must be set on rotation")
}

func TestAdminRotateAPIKey_NotFound(t *testing.T) {
	svc := &mockAdminAPIKeyService{
		rotateAPIKeyFn: func(_ context.Context, _ string) (*api.AdminAPIKeyWithSecret, error) {
			return nil, fmt.Errorf("api key not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminAPIKeyRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/apikeys/nonexistent/rotate", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
