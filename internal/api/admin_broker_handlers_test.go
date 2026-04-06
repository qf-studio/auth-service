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

// --- Mock AdminBrokerService ---

type mockAdminBrokerService struct {
	listCredentialsFn  func(ctx context.Context, page, perPage int, ownerClientID string) (*api.AdminBrokerCredentialList, error)
	getCredentialFn    func(ctx context.Context, credentialID string) (*api.AdminBrokerCredential, error)
	createCredentialFn func(ctx context.Context, req *api.CreateBrokerCredentialRequest) (*api.AdminBrokerCredentialWithSecret, error)
	updateCredentialFn func(ctx context.Context, credentialID string, req *api.UpdateBrokerCredentialRequest) (*api.AdminBrokerCredential, error)
	deleteCredentialFn func(ctx context.Context, credentialID string) error
	rotateCredentialFn func(ctx context.Context, credentialID string) (*api.AdminBrokerCredentialWithSecret, error)
}

func (m *mockAdminBrokerService) ListCredentials(ctx context.Context, page, perPage int, ownerClientID string) (*api.AdminBrokerCredentialList, error) {
	if m.listCredentialsFn != nil {
		return m.listCredentialsFn(ctx, page, perPage, ownerClientID)
	}
	return &api.AdminBrokerCredentialList{
		Credentials: []api.AdminBrokerCredential{{
			ID:             "cred-1",
			OwnerClientID:  "c1",
			TargetName:     "openai",
			CredentialType: "api_key",
			Scopes:         []string{"chat"},
			Status:         "active",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminBrokerService) GetCredential(ctx context.Context, credentialID string) (*api.AdminBrokerCredential, error) {
	if m.getCredentialFn != nil {
		return m.getCredentialFn(ctx, credentialID)
	}
	return &api.AdminBrokerCredential{
		ID:             credentialID,
		OwnerClientID:  "c1",
		TargetName:     "openai",
		CredentialType: "api_key",
		Scopes:         []string{"chat"},
		Status:         "active",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}, nil
}

func (m *mockAdminBrokerService) CreateCredential(ctx context.Context, req *api.CreateBrokerCredentialRequest) (*api.AdminBrokerCredentialWithSecret, error) {
	if m.createCredentialFn != nil {
		return m.createCredentialFn(ctx, req)
	}
	return &api.AdminBrokerCredentialWithSecret{
		AdminBrokerCredential: api.AdminBrokerCredential{
			ID:             "new-cred",
			OwnerClientID:  req.OwnerClientID,
			TargetName:     req.TargetName,
			CredentialType: req.CredentialType,
			Scopes:         req.Scopes,
			Status:         "active",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		Secret: "sk-secret-value-for-testing",
	}, nil
}

func (m *mockAdminBrokerService) UpdateCredential(ctx context.Context, credentialID string, req *api.UpdateBrokerCredentialRequest) (*api.AdminBrokerCredential, error) {
	if m.updateCredentialFn != nil {
		return m.updateCredentialFn(ctx, credentialID, req)
	}
	targetName := "openai"
	if req.TargetName != nil {
		targetName = *req.TargetName
	}
	return &api.AdminBrokerCredential{
		ID:             credentialID,
		OwnerClientID:  "c1",
		TargetName:     targetName,
		CredentialType: "api_key",
		Scopes:         req.Scopes,
		Status:         "active",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}, nil
}

func (m *mockAdminBrokerService) DeleteCredential(ctx context.Context, credentialID string) error {
	if m.deleteCredentialFn != nil {
		return m.deleteCredentialFn(ctx, credentialID)
	}
	return nil
}

func (m *mockAdminBrokerService) RotateCredential(ctx context.Context, credentialID string) (*api.AdminBrokerCredentialWithSecret, error) {
	if m.rotateCredentialFn != nil {
		return m.rotateCredentialFn(ctx, credentialID)
	}
	graceEnd := time.Now().Add(24 * time.Hour)
	return &api.AdminBrokerCredentialWithSecret{
		AdminBrokerCredential: api.AdminBrokerCredential{
			ID:             credentialID,
			OwnerClientID:  "c1",
			TargetName:     "openai",
			CredentialType: "api_key",
			Scopes:         []string{"chat"},
			Status:         "active",
			CreatedAt:      time.Now(),
			UpdatedAt:      time.Now(),
		},
		Secret:          "sk-new-rotated-secret",
		GracePeriodEnds: &graceEnd,
	}, nil
}

// --- Helper ---

func newAdminBrokerRouter(brokerSvc api.AdminBrokerService) *gin.Engine {
	svc := &api.AdminServices{Brokers: brokerSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List Credentials ---

func TestAdminListBrokerCredentials_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodGet, "/admin/credentials", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminBrokerCredentialList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Credentials, 1)
}

func TestAdminListBrokerCredentials_Pagination(t *testing.T) {
	svc := &mockAdminBrokerService{
		listCredentialsFn: func(_ context.Context, page, perPage int, ownerClientID string) (*api.AdminBrokerCredentialList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			assert.Equal(t, "", ownerClientID)
			return &api.AdminBrokerCredentialList{Credentials: []api.AdminBrokerCredential{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/credentials?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminBrokerCredentialList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListBrokerCredentials_FilterByOwner(t *testing.T) {
	svc := &mockAdminBrokerService{
		listCredentialsFn: func(_ context.Context, page, perPage int, ownerClientID string) (*api.AdminBrokerCredentialList, error) {
			assert.Equal(t, "client-123", ownerClientID)
			return &api.AdminBrokerCredentialList{Credentials: []api.AdminBrokerCredential{}, Total: 0, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/credentials?owner_client_id=client-123", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminListBrokerCredentials_ServiceError(t *testing.T) {
	svc := &mockAdminBrokerService{
		listCredentialsFn: func(_ context.Context, _, _ int, _ string) (*api.AdminBrokerCredentialList, error) {
			return nil, fmt.Errorf("list failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/credentials", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get Credential ---

func TestAdminGetBrokerCredential_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodGet, "/admin/credentials/cred-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminBrokerCredential
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "cred-1", resp.ID)
}

func TestAdminGetBrokerCredential_NotFound(t *testing.T) {
	svc := &mockAdminBrokerService{
		getCredentialFn: func(_ context.Context, _ string) (*api.AdminBrokerCredential, error) {
			return nil, fmt.Errorf("credential not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/credentials/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create Credential ---

func TestAdminCreateBrokerCredential_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	body := map[string]interface{}{
		"owner_client_id": "550e8400-e29b-41d4-a716-446655440000",
		"target_name":     "openai",
		"credential_type": "api_key",
		"scopes":          []string{"chat"},
	}
	w := doRequest(r, http.MethodPost, "/admin/credentials", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminBrokerCredentialWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "openai", resp.TargetName)
	assert.NotEmpty(t, resp.Secret, "secret must be returned on create")
}

func TestAdminCreateBrokerCredential_MissingOwnerClientID(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	body := map[string]interface{}{
		"target_name":     "openai",
		"credential_type": "api_key",
	}
	w := doRequest(r, http.MethodPost, "/admin/credentials", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateBrokerCredential_InvalidCredentialType(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	body := map[string]interface{}{
		"owner_client_id": "550e8400-e29b-41d4-a716-446655440000",
		"target_name":     "openai",
		"credential_type": "invalid_type",
	}
	w := doRequest(r, http.MethodPost, "/admin/credentials", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateBrokerCredential_InvalidJSON(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodPost, "/admin/credentials", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateBrokerCredential_ServiceError(t *testing.T) {
	svc := &mockAdminBrokerService{
		createCredentialFn: func(_ context.Context, _ *api.CreateBrokerCredentialRequest) (*api.AdminBrokerCredentialWithSecret, error) {
			return nil, fmt.Errorf("create failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminBrokerRouter(svc)
	body := map[string]interface{}{
		"owner_client_id": "550e8400-e29b-41d4-a716-446655440000",
		"target_name":     "openai",
		"credential_type": "api_key",
	}
	w := doRequest(r, http.MethodPost, "/admin/credentials", body)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Update Credential ---

func TestAdminUpdateBrokerCredential_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	name := "updated-target"
	body := map[string]interface{}{"target_name": name}
	w := doRequest(r, http.MethodPatch, "/admin/credentials/cred-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminBrokerCredential
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "updated-target", resp.TargetName)
}

func TestAdminUpdateBrokerCredential_NotFound(t *testing.T) {
	svc := &mockAdminBrokerService{
		updateCredentialFn: func(_ context.Context, _ string, _ *api.UpdateBrokerCredentialRequest) (*api.AdminBrokerCredential, error) {
			return nil, fmt.Errorf("credential not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminBrokerRouter(svc)
	body := map[string]interface{}{"target_name": "nope"}
	w := doRequest(r, http.MethodPatch, "/admin/credentials/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdateBrokerCredential_InvalidJSON(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodPatch, "/admin/credentials/cred-1", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Delete Credential ---

func TestAdminDeleteBrokerCredential_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodDelete, "/admin/credentials/cred-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteBrokerCredential_NotFound(t *testing.T) {
	svc := &mockAdminBrokerService{
		deleteCredentialFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("credential not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/credentials/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Rotate Credential ---

func TestAdminRotateBrokerCredential_Success(t *testing.T) {
	r := newAdminBrokerRouter(&mockAdminBrokerService{})
	w := doRequest(r, http.MethodPost, "/admin/credentials/cred-1/rotate", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminBrokerCredentialWithSecret
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotEmpty(t, resp.Secret, "new secret must be returned on rotation")
	assert.NotNil(t, resp.GracePeriodEnds, "grace period must be set on rotation")
}

func TestAdminRotateBrokerCredential_NotFound(t *testing.T) {
	svc := &mockAdminBrokerService{
		rotateCredentialFn: func(_ context.Context, _ string) (*api.AdminBrokerCredentialWithSecret, error) {
			return nil, fmt.Errorf("credential not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminBrokerRouter(svc)
	w := doRequest(r, http.MethodPost, "/admin/credentials/nonexistent/rotate", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}
