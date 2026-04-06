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

// --- Mock AdminSAMLService ---

type mockAdminSAMLService struct {
	listIdPsFn              func(ctx context.Context, page, perPage int) (*api.AdminSAMLIdPList, error)
	getIdPFn                func(ctx context.Context, idpID string) (*api.AdminSAMLIdP, error)
	createIdPFn             func(ctx context.Context, req *api.CreateSAMLIdPRequest) (*api.AdminSAMLIdP, error)
	updateIdPFn             func(ctx context.Context, idpID string, req *api.UpdateSAMLIdPRequest) (*api.AdminSAMLIdP, error)
	deleteIdPFn             func(ctx context.Context, idpID string) error
	importMetadataFn        func(ctx context.Context, idpID string, req *api.ImportSAMLMetadataRequest) (*api.AdminSAMLIdP, error)
	exportMetadataFn        func(ctx context.Context, idpID string) ([]byte, error)
	updateAttributeMappingFn func(ctx context.Context, idpID string, req *api.SAMLAttributeMappingRequest) (*api.AdminSAMLIdP, error)
	getAttributeMappingFn   func(ctx context.Context, idpID string) (map[string]string, error)
}

var testIdP = api.AdminSAMLIdP{
	ID:          "idp-1",
	Name:        "Test IdP",
	EntityID:    "https://idp.example.com",
	SSOURL:      "https://idp.example.com/sso",
	Certificate: "MIICpDCCAYwCCQDU+pQ4pHgCmDANBg...",
	Enabled:     true,
	CreatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
	UpdatedAt:   time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
}

func (m *mockAdminSAMLService) ListIdPs(ctx context.Context, page, perPage int) (*api.AdminSAMLIdPList, error) {
	if m.listIdPsFn != nil {
		return m.listIdPsFn(ctx, page, perPage)
	}
	return &api.AdminSAMLIdPList{
		IdPs:    []api.AdminSAMLIdP{testIdP},
		Total:   1,
		Page:    page,
		PerPage: perPage,
	}, nil
}

func (m *mockAdminSAMLService) GetIdP(ctx context.Context, idpID string) (*api.AdminSAMLIdP, error) {
	if m.getIdPFn != nil {
		return m.getIdPFn(ctx, idpID)
	}
	idp := testIdP
	idp.ID = idpID
	return &idp, nil
}

func (m *mockAdminSAMLService) CreateIdP(ctx context.Context, req *api.CreateSAMLIdPRequest) (*api.AdminSAMLIdP, error) {
	if m.createIdPFn != nil {
		return m.createIdPFn(ctx, req)
	}
	return &api.AdminSAMLIdP{
		ID:          "new-idp",
		Name:        req.Name,
		EntityID:    req.EntityID,
		SSOURL:      req.SSOURL,
		SLOURL:      req.SLOURL,
		Certificate: req.Certificate,
		Enabled:     true,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}, nil
}

func (m *mockAdminSAMLService) UpdateIdP(ctx context.Context, idpID string, req *api.UpdateSAMLIdPRequest) (*api.AdminSAMLIdP, error) {
	if m.updateIdPFn != nil {
		return m.updateIdPFn(ctx, idpID, req)
	}
	idp := testIdP
	idp.ID = idpID
	if req.Name != nil {
		idp.Name = *req.Name
	}
	return &idp, nil
}

func (m *mockAdminSAMLService) DeleteIdP(ctx context.Context, idpID string) error {
	if m.deleteIdPFn != nil {
		return m.deleteIdPFn(ctx, idpID)
	}
	return nil
}

func (m *mockAdminSAMLService) ImportMetadata(ctx context.Context, idpID string, req *api.ImportSAMLMetadataRequest) (*api.AdminSAMLIdP, error) {
	if m.importMetadataFn != nil {
		return m.importMetadataFn(ctx, idpID, req)
	}
	idp := testIdP
	idp.ID = idpID
	return &idp, nil
}

func (m *mockAdminSAMLService) ExportMetadata(ctx context.Context, idpID string) ([]byte, error) {
	if m.exportMetadataFn != nil {
		return m.exportMetadataFn(ctx, idpID)
	}
	return []byte(`<EntityDescriptor entityID="https://idp.example.com"/>`), nil
}

func (m *mockAdminSAMLService) UpdateAttributeMapping(ctx context.Context, idpID string, req *api.SAMLAttributeMappingRequest) (*api.AdminSAMLIdP, error) {
	if m.updateAttributeMappingFn != nil {
		return m.updateAttributeMappingFn(ctx, idpID, req)
	}
	idp := testIdP
	idp.ID = idpID
	idp.AttributeMapping = req.AttributeMapping
	return &idp, nil
}

func (m *mockAdminSAMLService) GetAttributeMapping(ctx context.Context, idpID string) (map[string]string, error) {
	if m.getAttributeMappingFn != nil {
		return m.getAttributeMappingFn(ctx, idpID)
	}
	return map[string]string{
		"email":      "urn:oid:0.9.2342.19200300.100.1.3",
		"first_name": "urn:oid:2.5.4.42",
		"last_name":  "urn:oid:2.5.4.4",
	}, nil
}

// --- Helper ---

func newAdminSAMLRouter(samlSvc api.AdminSAMLService) *gin.Engine {
	svc := &api.AdminServices{SAML: samlSvc}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// --- List IdPs ---

func TestAdminListSAMLIdPs_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodGet, "/admin/saml/idps", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdPList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.IdPs, 1)
}

func TestAdminListSAMLIdPs_Pagination(t *testing.T) {
	svc := &mockAdminSAMLService{
		listIdPsFn: func(_ context.Context, page, perPage int) (*api.AdminSAMLIdPList, error) {
			assert.Equal(t, 2, page)
			assert.Equal(t, 10, perPage)
			return &api.AdminSAMLIdPList{IdPs: []api.AdminSAMLIdP{}, Total: 50, Page: page, PerPage: perPage}, nil
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/saml/idps?page=2&per_page=10", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdPList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.Page)
	assert.Equal(t, 10, resp.PerPage)
}

func TestAdminListSAMLIdPs_ServiceError(t *testing.T) {
	svc := &mockAdminSAMLService{
		listIdPsFn: func(_ context.Context, _, _ int) (*api.AdminSAMLIdPList, error) {
			return nil, fmt.Errorf("list failed: %w", api.ErrInternalError)
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/saml/idps", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get IdP ---

func TestAdminGetSAMLIdP_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/idp-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdP
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "idp-1", resp.ID)
}

func TestAdminGetSAMLIdP_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		getIdPFn: func(_ context.Context, _ string) (*api.AdminSAMLIdP, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create IdP ---

func TestAdminCreateSAMLIdP_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{
		"name":        "Okta IdP",
		"entity_id":   "https://okta.example.com",
		"sso_url":     "https://okta.example.com/sso",
		"certificate": "MIICpDCCAYwCCQDU+pQ4pHgCmDANBg...",
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminSAMLIdP
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Okta IdP", resp.Name)
	assert.Equal(t, "https://okta.example.com", resp.EntityID)
}

func TestAdminCreateSAMLIdP_MissingName(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{
		"entity_id":   "https://okta.example.com",
		"sso_url":     "https://okta.example.com/sso",
		"certificate": "MIICpDCCAYwCCQDU+pQ4pHgCmDANBg...",
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateSAMLIdP_MissingEntityID(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{
		"name":        "Okta IdP",
		"sso_url":     "https://okta.example.com/sso",
		"certificate": "MIICpDCCAYwCCQDU+pQ4pHgCmDANBg...",
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreateSAMLIdP_InvalidJSON(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodPost, "/admin/saml/idps", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreateSAMLIdP_ServiceError(t *testing.T) {
	svc := &mockAdminSAMLService{
		createIdPFn: func(_ context.Context, _ *api.CreateSAMLIdPRequest) (*api.AdminSAMLIdP, error) {
			return nil, fmt.Errorf("create failed: %w", api.ErrConflict)
		},
	}
	r := newAdminSAMLRouter(svc)
	body := map[string]interface{}{
		"name":        "Okta IdP",
		"entity_id":   "https://okta.example.com",
		"sso_url":     "https://okta.example.com/sso",
		"certificate": "MIICpDCCAYwCCQDU+pQ4pHgCmDANBg...",
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update IdP ---

func TestAdminUpdateSAMLIdP_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	name := "Updated IdP"
	body := map[string]interface{}{"name": name}
	w := doRequest(r, http.MethodPatch, "/admin/saml/idps/idp-1", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdP
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "Updated IdP", resp.Name)
}

func TestAdminUpdateSAMLIdP_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		updateIdPFn: func(_ context.Context, _ string, _ *api.UpdateSAMLIdPRequest) (*api.AdminSAMLIdP, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	body := map[string]interface{}{"name": "test"}
	w := doRequest(r, http.MethodPatch, "/admin/saml/idps/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdateSAMLIdP_InvalidJSON(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodPatch, "/admin/saml/idps/idp-1", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Delete IdP ---

func TestAdminDeleteSAMLIdP_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodDelete, "/admin/saml/idps/idp-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeleteSAMLIdP_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		deleteIdPFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodDelete, "/admin/saml/idps/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Import Metadata ---

func TestAdminImportSAMLMetadata_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{
		"metadata_xml": `<EntityDescriptor entityID="https://idp.example.com"/>`,
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps/idp-1/metadata", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdP
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "idp-1", resp.ID)
}

func TestAdminImportSAMLMetadata_MissingXML(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps/idp-1/metadata", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminImportSAMLMetadata_InvalidJSON(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodPost, "/admin/saml/idps/idp-1/metadata", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminImportSAMLMetadata_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		importMetadataFn: func(_ context.Context, _ string, _ *api.ImportSAMLMetadataRequest) (*api.AdminSAMLIdP, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	body := map[string]interface{}{
		"metadata_xml": `<EntityDescriptor entityID="https://idp.example.com"/>`,
	}
	w := doRequest(r, http.MethodPost, "/admin/saml/idps/nonexistent/metadata", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Export Metadata ---

func TestAdminExportSAMLMetadata_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/idp-1/metadata", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/xml")
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
}

func TestAdminExportSAMLMetadata_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		exportMetadataFn: func(_ context.Context, _ string) ([]byte, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/nonexistent/metadata", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Update Attribute Mapping ---

func TestAdminUpdateSAMLAttributeMapping_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{
		"attribute_mapping": map[string]string{
			"email":      "urn:oid:0.9.2342.19200300.100.1.3",
			"first_name": "urn:oid:2.5.4.42",
		},
	}
	w := doRequest(r, http.MethodPut, "/admin/saml/idps/idp-1/attribute-mapping", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminSAMLIdP
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.NotNil(t, resp.AttributeMapping)
}

func TestAdminUpdateSAMLAttributeMapping_MissingMapping(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	body := map[string]interface{}{}
	w := doRequest(r, http.MethodPut, "/admin/saml/idps/idp-1/attribute-mapping", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminUpdateSAMLAttributeMapping_InvalidJSON(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodPut, "/admin/saml/idps/idp-1/attribute-mapping", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminUpdateSAMLAttributeMapping_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		updateAttributeMappingFn: func(_ context.Context, _ string, _ *api.SAMLAttributeMappingRequest) (*api.AdminSAMLIdP, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	body := map[string]interface{}{
		"attribute_mapping": map[string]string{"email": "urn:oid:0.9.2342.19200300.100.1.3"},
	}
	w := doRequest(r, http.MethodPut, "/admin/saml/idps/nonexistent/attribute-mapping", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Get Attribute Mapping ---

func TestAdminGetSAMLAttributeMapping_Success(t *testing.T) {
	r := newAdminSAMLRouter(&mockAdminSAMLService{})
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/idp-1/attribute-mapping", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "attribute_mapping")
	assert.Contains(t, w.Body.String(), "email")
}

func TestAdminGetSAMLAttributeMapping_NotFound(t *testing.T) {
	svc := &mockAdminSAMLService{
		getAttributeMappingFn: func(_ context.Context, _ string) (map[string]string, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newAdminSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/admin/saml/idps/nonexistent/attribute-mapping", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Route registration ---

func TestAdminSAMLRoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.AdminServices{
		// SAML is nil
	}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/saml/idps"},
		{http.MethodGet, "/admin/saml/idps/test"},
		{http.MethodPost, "/admin/saml/idps"},
		{http.MethodPatch, "/admin/saml/idps/test"},
		{http.MethodDelete, "/admin/saml/idps/test"},
		{http.MethodPost, "/admin/saml/idps/test/metadata"},
		{http.MethodGet, "/admin/saml/idps/test/metadata"},
		{http.MethodPut, "/admin/saml/idps/test/attribute-mapping"},
		{http.MethodGet, "/admin/saml/idps/test/attribute-mapping"},
	}

	for _, tt := range tests {
		w := doRequest(r, tt.method, tt.path, nil)
		require.Equal(t, http.StatusNotFound, w.Code, "route %s %s should not be registered", tt.method, tt.path)
	}
}
