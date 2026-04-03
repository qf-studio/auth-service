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

// --- Mock AdminClientService ---

type mockAdminClientService struct {
	listClientsFn  func(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error)
	getClientFn    func(ctx context.Context, clientID string) (*api.AdminClient, error)
	createClientFn func(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error)
	updateClientFn func(ctx context.Context, clientID string, req *api.UpdateClientRequest) (*api.AdminClient, error)
	deleteClientFn func(ctx context.Context, clientID string) error
	rotateSecretFn func(ctx context.Context, clientID string) (*api.AdminClientWithSecret, error)
}

func (m *mockAdminClientService) ListClients(ctx context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error) {
	if m.listClientsFn != nil {
		return m.listClientsFn(ctx, page, perPage, includeDeleted)
	}
	return &api.AdminClientList{
		Clients: []api.AdminClient{{ID: "c1", Name: "test-client", ClientType: "service", Scopes: []string{"read:users"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminClientService) GetClient(ctx context.Context, clientID string) (*api.AdminClient, error) {
	if m.getClientFn != nil {
		return m.getClientFn(ctx, clientID)
	}
	return &api.AdminClient{ID: clientID, Name: "test-client", ClientType: "service", Scopes: []string{"read:users"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminClientService) CreateClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	if m.createClientFn != nil {
		return m.createClientFn(ctx, req)
	}
	return &api.AdminClientWithSecret{
		AdminClient: api.AdminClient{
			ID:         "new-client",
			Name:       req.Name,
			ClientType: req.ClientType,
			Scopes:     req.Scopes,
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		ClientSecret: "qf_cs_generated_secret_value",
	}, nil
}

func (m *mockAdminClientService) UpdateClient(ctx context.Context, clientID string, req *api.UpdateClientRequest) (*api.AdminClient, error) {
	if m.updateClientFn != nil {
		return m.updateClientFn(ctx, clientID, req)
	}
	name := "test-client"
	if req.Name != nil {
		name = *req.Name
	}
	return &api.AdminClient{ID: clientID, Name: name, ClientType: "service", Scopes: req.Scopes, CreatedAt: time.Now(), UpdatedAt: time.Now()}, nil
}

func (m *mockAdminClientService) DeleteClient(ctx context.Context, clientID string) error {
	if m.deleteClientFn != nil {
		return m.deleteClientFn(ctx, clientID)
	}
	return nil
}

func (m *mockAdminClientService) RotateSecret(ctx context.Context, clientID string) (*api.AdminClientWithSecret, error) {
	if m.rotateSecretFn != nil {
		return m.rotateSecretFn(ctx, clientID)
	}
	graceEnd := time.Now().Add(24 * time.Hour)
	return &api.AdminClientWithSecret{
		AdminClient: api.AdminClient{
			ID:         clientID,
			Name:       "test-client",
			ClientType: "service",
			Scopes:     []string{"read:users"},
			CreatedAt:  time.Now(),
			UpdatedAt:  time.Now(),
		},
		ClientSecret:    "qf_cs_new_rotated_secret",
		GracePeriodEnds: &graceEnd,
	}, nil
}

// --- Helper ---

func newAdminClientRouter(clientSvc api.AdminClientService) *gin.Engine {
	svc := &api.AdminServices{Clients: clientSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List Clients ---

func TestAdminListClients_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	w := doRequest(r, http.MethodGet, "/admin/clients", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminClientList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Clients, 1)
}

func TestAdminListClients_Pagination(t *testing.T) {
	svc := &mockAdminClientService{
		listClientsFn: func(_ context.Context, page, perPage int, includeDeleted bool) (*api.AdminClientList, error) {
			assert.Equal(t, 3, page)
			assert.Equal(t, 5, perPage)
			assert.False(t, includeDeleted)
			return &api.AdminClientList{Clients: []api.AdminClient{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminClientRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/clients?page=3&per_page=5", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminClientList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 3, resp.Page)
	assert.Equal(t, 5, resp.PerPage)
}

// --- Get Client ---

func TestAdminGetClient_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	w := doRequest(r, http.MethodGet, "/admin/clients/client-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminClient
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "client-1", resp.ID)
}

func TestAdminGetClient_NotFound(t *testing.T) {
	svc := &mockAdminClientService{
		getClientFn: func(_ context.Context, _ string) (*api.AdminClient, error) {
			return nil, fmt.Errorf("client not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminClientRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/clients/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create Client ---

func TestAdminCreateClient_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	body := map[string]interface{}{
		"name":        "my-service",
		"client_type": "service",
		"scopes":      []string{"read:users", "write:users"},
	}
	w := doRequest(r, http.MethodPost, "/admin/clients", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminClientWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "my-service", resp.Name)
	assert.Equal(t, "service", resp.ClientType)
	assert.NotEmpty(t, resp.ClientSecret, "secret must be returned on create")
}

func TestAdminCreateClient_AgentType(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	body := map[string]interface{}{
		"name":        "my-agent",
		"client_type": "agent",
	}
	w := doRequest(r, http.MethodPost, "/admin/clients", body)

	assert.Equal(t, http.StatusCreated, w.Code)
}

func TestAdminCreateClient_InvalidType(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	body := map[string]interface{}{
		"name":        "bad-client",
		"client_type": "user",
	}
	w := doRequest(r, http.MethodPost, "/admin/clients", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateClient_MissingName(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	body := map[string]interface{}{
		"client_type": "service",
	}
	w := doRequest(r, http.MethodPost, "/admin/clients", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateClient_Conflict(t *testing.T) {
	svc := &mockAdminClientService{
		createClientFn: func(_ context.Context, _ *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
			return nil, fmt.Errorf("client name exists: %w", api.ErrConflict)
		},
	}
	r := newAdminClientRouter(svc)
	body := map[string]interface{}{
		"name":        "dup-client",
		"client_type": "service",
	}
	w := doRequest(r, http.MethodPost, "/admin/clients", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update Client ---

func TestAdminUpdateClient_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	name := "updated-name"
	body := map[string]interface{}{"name": name}
	w := doRequest(r, http.MethodPatch, "/admin/clients/client-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminClient
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "updated-name", resp.Name)
}

func TestAdminUpdateClient_NotFound(t *testing.T) {
	svc := &mockAdminClientService{
		updateClientFn: func(_ context.Context, _ string, _ *api.UpdateClientRequest) (*api.AdminClient, error) {
			return nil, fmt.Errorf("client not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminClientRouter(svc)
	body := map[string]interface{}{"name": "nope"}
	w := doRequest(r, http.MethodPatch, "/admin/clients/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Delete Client ---

func TestAdminDeleteClient_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	w := doRequest(r, http.MethodDelete, "/admin/clients/client-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteClient_NotFound(t *testing.T) {
	svc := &mockAdminClientService{
		deleteClientFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("client not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminClientRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/clients/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Rotate Secret ---

func TestAdminRotateSecret_Success(t *testing.T) {
	r := newAdminClientRouter(&mockAdminClientService{})
	w := doRequest(r, http.MethodPost, "/admin/clients/client-1/rotate-secret", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminClientWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.ClientSecret, "new secret must be returned on rotation")
	assert.NotNil(t, resp.GracePeriodEnds, "grace period must be set on rotation")
}

func TestAdminRotateSecret_NotFound(t *testing.T) {
	svc := &mockAdminClientService{
		rotateSecretFn: func(_ context.Context, _ string) (*api.AdminClientWithSecret, error) {
			return nil, fmt.Errorf("client not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminClientRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/clients/nonexistent/rotate-secret", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
