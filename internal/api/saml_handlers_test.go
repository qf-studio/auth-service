package api_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock SAMLService ---

type mockSAMLService struct {
	getMetadataFn    func(ctx context.Context, idpID string) (*api.SAMLMetadataResponse, error)
	initiateSSOFn    func(ctx context.Context, idpID, relayState string) (*api.SAMLLoginResult, error)
	processResponseFn func(ctx context.Context, samlResponse, relayState string) (*api.SAMLACSResult, error)
}

func (m *mockSAMLService) GetMetadata(ctx context.Context, idpID string) (*api.SAMLMetadataResponse, error) {
	if m.getMetadataFn != nil {
		return m.getMetadataFn(ctx, idpID)
	}
	return &api.SAMLMetadataResponse{
		XML: []byte(`<EntityDescriptor entityID="https://sp.example.com"/>`),
	}, nil
}

func (m *mockSAMLService) InitiateSSO(ctx context.Context, idpID, relayState string) (*api.SAMLLoginResult, error) {
	if m.initiateSSOFn != nil {
		return m.initiateSSOFn(ctx, idpID, relayState)
	}
	return &api.SAMLLoginResult{
		RedirectURL: "https://idp.example.com/sso?SAMLRequest=encoded",
	}, nil
}

func (m *mockSAMLService) ProcessResponse(ctx context.Context, samlResponse, relayState string) (*api.SAMLACSResult, error) {
	if m.processResponseFn != nil {
		return m.processResponseFn(ctx, samlResponse, relayState)
	}
	return &api.SAMLACSResult{
		AccessToken:  "qf_at_test_saml",
		RefreshToken: "qf_rt_test_saml",
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		UserID:       "user-saml-1",
	}, nil
}

// --- Helper ---

func newSAMLRouter(samlSvc api.SAMLService) *gin.Engine {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		SAML:  samlSvc,
	}
	return api.NewPublicRouter(svc, nil, health.NewService())
}

func doFormPost(router *gin.Engine, path string, formData url.Values) *httptest.ResponseRecorder {
	body := formData.Encode()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	return w
}

// --- Metadata ---

func TestSAMLMetadata_Success(t *testing.T) {
	r := newSAMLRouter(&mockSAMLService{})
	w := doRequest(r, http.MethodGet, "/auth/saml/metadata", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/samlmetadata+xml")
	assert.Contains(t, w.Body.String(), "EntityDescriptor")
}

func TestSAMLMetadata_WithIdP(t *testing.T) {
	svc := &mockSAMLService{
		getMetadataFn: func(_ context.Context, idpID string) (*api.SAMLMetadataResponse, error) {
			assert.Equal(t, "idp-1", idpID)
			return &api.SAMLMetadataResponse{
				XML: []byte(`<EntityDescriptor entityID="https://sp.example.com/idp-1"/>`),
			}, nil
		},
	}
	r := newSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/saml/metadata?idp_id=idp-1", nil)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "idp-1")
}

func TestSAMLMetadata_ServiceError(t *testing.T) {
	svc := &mockSAMLService{
		getMetadataFn: func(_ context.Context, _ string) (*api.SAMLMetadataResponse, error) {
			return nil, fmt.Errorf("metadata error: %w", api.ErrNotFound)
		},
	}
	r := newSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/saml/metadata", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Login ---

func TestSAMLLogin_Success(t *testing.T) {
	r := newSAMLRouter(&mockSAMLService{})
	w := doRequest(r, http.MethodGet, "/auth/saml/login?idp_id=idp-1", nil)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "https://idp.example.com/sso?SAMLRequest=encoded", w.Header().Get("Location"))
}

func TestSAMLLogin_MissingIdPID(t *testing.T) {
	r := newSAMLRouter(&mockSAMLService{})
	w := doRequest(r, http.MethodGet, "/auth/saml/login", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSAMLLogin_WithRelayState(t *testing.T) {
	svc := &mockSAMLService{
		initiateSSOFn: func(_ context.Context, idpID, relayState string) (*api.SAMLLoginResult, error) {
			assert.Equal(t, "idp-1", idpID)
			assert.Equal(t, "/dashboard", relayState)
			return &api.SAMLLoginResult{
				RedirectURL: "https://idp.example.com/sso?SAMLRequest=encoded&RelayState=%2Fdashboard",
			}, nil
		},
	}
	r := newSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/saml/login?idp_id=idp-1&relay_state=/dashboard", nil)

	assert.Equal(t, http.StatusFound, w.Code)
}

func TestSAMLLogin_ServiceError(t *testing.T) {
	svc := &mockSAMLService{
		initiateSSOFn: func(_ context.Context, _, _ string) (*api.SAMLLoginResult, error) {
			return nil, fmt.Errorf("idp not found: %w", api.ErrNotFound)
		},
	}
	r := newSAMLRouter(svc)
	w := doRequest(r, http.MethodGet, "/auth/saml/login?idp_id=nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- ACS ---

func TestSAMLACS_Success(t *testing.T) {
	r := newSAMLRouter(&mockSAMLService{})
	form := url.Values{
		"SAMLResponse": {"PHNhbWxwOlJlc3BvbnNlLz4="}, // base64 encoded dummy
		"RelayState":   {"/dashboard"},
	}
	w := doFormPost(r, "/auth/saml/acs", form)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "qf_at_test_saml")
	assert.Contains(t, w.Body.String(), "qf_rt_test_saml")
}

func TestSAMLACS_MissingSAMLResponse(t *testing.T) {
	r := newSAMLRouter(&mockSAMLService{})
	form := url.Values{
		"RelayState": {"/dashboard"},
	}
	w := doFormPost(r, "/auth/saml/acs", form)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestSAMLACS_ServiceError(t *testing.T) {
	svc := &mockSAMLService{
		processResponseFn: func(_ context.Context, _, _ string) (*api.SAMLACSResult, error) {
			return nil, fmt.Errorf("invalid assertion: %w", api.ErrUnauthorized)
		},
	}
	r := newSAMLRouter(svc)
	form := url.Values{
		"SAMLResponse": {"PHNhbWxwOlJlc3BvbnNlLz4="},
	}
	w := doFormPost(r, "/auth/saml/acs", form)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestSAMLACS_JITProvisioned(t *testing.T) {
	svc := &mockSAMLService{
		processResponseFn: func(_ context.Context, _, _ string) (*api.SAMLACSResult, error) {
			return &api.SAMLACSResult{
				AccessToken:    "qf_at_jit",
				RefreshToken:   "qf_rt_jit",
				TokenType:      "Bearer",
				ExpiresIn:      3600,
				UserID:         "user-jit-1",
				JITProvisioned: true,
			}, nil
		},
	}
	r := newSAMLRouter(svc)
	form := url.Values{
		"SAMLResponse": {"PHNhbWxwOlJlc3BvbnNlLz4="},
	}
	w := doFormPost(r, "/auth/saml/acs", form)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), `"jit_provisioned":true`)
}

func TestSAMLACS_InternalError(t *testing.T) {
	svc := &mockSAMLService{
		processResponseFn: func(_ context.Context, _, _ string) (*api.SAMLACSResult, error) {
			return nil, fmt.Errorf("processing failed: %w", api.ErrInternalError)
		},
	}
	r := newSAMLRouter(svc)
	form := url.Values{
		"SAMLResponse": {"PHNhbWxwOlJlc3BvbnNlLz4="},
	}
	w := doFormPost(r, "/auth/saml/acs", form)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Route registration ---

func TestSAMLRoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.Services{
		Auth:  &mockAuthService{},
		Token: &mockTokenService{},
		// SAML is nil
	}
	r := api.NewPublicRouter(svc, nil, health.NewService())

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/auth/saml/metadata"},
		{http.MethodGet, "/auth/saml/login?idp_id=test"},
		{http.MethodPost, "/auth/saml/acs"},
	}

	for _, tt := range tests {
		w := doRequest(r, tt.method, tt.path, nil)
		require.Equal(t, http.StatusNotFound, w.Code, "route %s %s should not be registered", tt.method, tt.path)
	}
}
