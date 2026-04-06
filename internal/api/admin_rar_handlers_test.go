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

// --- Mock AdminRARService ---

type mockAdminRARService struct {
	listRARTypesFn  func(ctx context.Context, page, perPage int) (*api.AdminRARTypeList, error)
	getRARTypeFn    func(ctx context.Context, rarType string) (*api.AdminRARType, error)
	createRARTypeFn func(ctx context.Context, req *api.CreateRARTypeRequest) (*api.AdminRARType, error)
	updateRARTypeFn func(ctx context.Context, rarType string, req *api.UpdateRARTypeRequest) (*api.AdminRARType, error)
	deleteRARTypeFn func(ctx context.Context, rarType string) error
}

func (m *mockAdminRARService) ListRARTypes(ctx context.Context, page, perPage int) (*api.AdminRARTypeList, error) {
	if m.listRARTypesFn != nil {
		return m.listRARTypesFn(ctx, page, perPage)
	}
	return &api.AdminRARTypeList{
		Types: []api.AdminRARType{{
			Type:        "payment_initiation",
			Description: "Payment initiation authorization",
			Actions:     []string{"initiate", "status"},
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminRARService) GetRARType(ctx context.Context, rarType string) (*api.AdminRARType, error) {
	if m.getRARTypeFn != nil {
		return m.getRARTypeFn(ctx, rarType)
	}
	return &api.AdminRARType{
		Type:        rarType,
		Description: "Test authorization type",
		Actions:     []string{"read", "write"},
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

func (m *mockAdminRARService) CreateRARType(ctx context.Context, req *api.CreateRARTypeRequest) (*api.AdminRARType, error) {
	if m.createRARTypeFn != nil {
		return m.createRARTypeFn(ctx, req)
	}
	return &api.AdminRARType{
		Type:        req.Type,
		Description: req.Description,
		Locations:   req.Locations,
		Actions:     req.Actions,
		DataTypes:   req.DataTypes,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

func (m *mockAdminRARService) UpdateRARType(ctx context.Context, rarType string, req *api.UpdateRARTypeRequest) (*api.AdminRARType, error) {
	if m.updateRARTypeFn != nil {
		return m.updateRARTypeFn(ctx, rarType, req)
	}
	desc := "Test authorization type"
	if req.Description != nil {
		desc = *req.Description
	}
	return &api.AdminRARType{
		Type:        rarType,
		Description: desc,
		Locations:   req.Locations,
		Actions:     req.Actions,
		DataTypes:   req.DataTypes,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

func (m *mockAdminRARService) DeleteRARType(ctx context.Context, rarType string) error {
	if m.deleteRARTypeFn != nil {
		return m.deleteRARTypeFn(ctx, rarType)
	}
	return nil
}

// --- Helper ---

func newAdminRARRouter(rarSvc api.AdminRARService) *gin.Engine {
	svc := &api.AdminServices{RAR: rarSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List RAR Types ---

func TestAdminListRARTypes_Success(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	w := doRequest(r, http.MethodGet, "/admin/rar/types", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminRARTypeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Types, 1)
	assert.Equal(t, "payment_initiation", resp.Types[0].Type)
}

func TestAdminListRARTypes_Pagination(t *testing.T) {
	svc := &mockAdminRARService{
		listRARTypesFn: func(_ context.Context, page, perPage int) (*api.AdminRARTypeList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			return &api.AdminRARTypeList{Types: []api.AdminRARType{}, Total: 25, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminRARRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rar/types?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminRARTypeList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListRARTypes_ServiceError(t *testing.T) {
	svc := &mockAdminRARService{
		listRARTypesFn: func(_ context.Context, _, _ int) (*api.AdminRARTypeList, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	r := newAdminRARRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rar/types", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get RAR Type ---

func TestAdminGetRARType_Success(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	w := doRequest(r, http.MethodGet, "/admin/rar/types/payment_initiation", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminRARType
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "payment_initiation", resp.Type)
}

func TestAdminGetRARType_NotFound(t *testing.T) {
	svc := &mockAdminRARService{
		getRARTypeFn: func(_ context.Context, _ string) (*api.AdminRARType, error) {
			return nil, fmt.Errorf("type not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminRARRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/rar/types/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create RAR Type ---

func TestAdminCreateRARType_Success(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	body := map[string]interface{}{
		"type":        "account_information",
		"description": "Access to account information",
		"actions":     []string{"list", "read"},
		"locations":   []string{"https://api.example.com/accounts"},
	}
	w := doRequest(r, http.MethodPost, "/admin/rar/types", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminRARType
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "account_information", resp.Type)
	assert.Equal(t, "Access to account information", resp.Description)
}

func TestAdminCreateRARType_MissingType(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	body := map[string]interface{}{
		"description": "Missing type field",
	}
	w := doRequest(r, http.MethodPost, "/admin/rar/types", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateRARType_MissingDescription(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	body := map[string]interface{}{
		"type": "payment_initiation",
	}
	w := doRequest(r, http.MethodPost, "/admin/rar/types", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateRARType_InvalidJSON(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	w := doRequest(r, http.MethodPost, "/admin/rar/types", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateRARType_ServiceError(t *testing.T) {
	svc := &mockAdminRARService{
		createRARTypeFn: func(_ context.Context, _ *api.CreateRARTypeRequest) (*api.AdminRARType, error) {
			return nil, fmt.Errorf("duplicate type: %w", api.ErrConflict)
		},
	}
	r := newAdminRARRouter(svc)
	body := map[string]interface{}{
		"type":        "payment_initiation",
		"description": "Duplicate",
	}
	w := doRequest(r, http.MethodPost, "/admin/rar/types", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update RAR Type ---

func TestAdminUpdateRARType_Success(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	body := map[string]interface{}{
		"description": "Updated description",
		"actions":     []string{"initiate", "status", "cancel"},
	}
	w := doRequest(r, http.MethodPatch, "/admin/rar/types/payment_initiation", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminRARType
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "payment_initiation", resp.Type)
}

func TestAdminUpdateRARType_InvalidJSON(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	w := doRequest(r, http.MethodPatch, "/admin/rar/types/payment_initiation", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUpdateRARType_NotFound(t *testing.T) {
	svc := &mockAdminRARService{
		updateRARTypeFn: func(_ context.Context, _ string, _ *api.UpdateRARTypeRequest) (*api.AdminRARType, error) {
			return nil, fmt.Errorf("type not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminRARRouter(svc)
	body := map[string]interface{}{
		"description": "Not going to work",
	}
	w := doRequest(r, http.MethodPatch, "/admin/rar/types/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Delete RAR Type ---

func TestAdminDeleteRARType_Success(t *testing.T) {
	r := newAdminRARRouter(&mockAdminRARService{})
	w := doRequest(r, http.MethodDelete, "/admin/rar/types/payment_initiation", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteRARType_NotFound(t *testing.T) {
	svc := &mockAdminRARService{
		deleteRARTypeFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("type not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminRARRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/rar/types/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminDeleteRARType_ServiceError(t *testing.T) {
	svc := &mockAdminRARService{
		deleteRARTypeFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	r := newAdminRARRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/rar/types/payment_initiation", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
