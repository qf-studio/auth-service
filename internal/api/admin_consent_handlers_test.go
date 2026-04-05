package api_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// ── Mock Consent Service ───────────────────────────────────────────────────

type mockConsentService struct {
	getLoginRequestFn   func(ctx context.Context, challenge string) (*api.LoginRequestInfo, error)
	acceptLoginFn       func(ctx context.Context, challenge string, req *api.AcceptLoginRequest) (*api.RedirectResponse, error)
	rejectLoginFn       func(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error)
	getConsentRequestFn func(ctx context.Context, challenge string) (*api.ConsentRequestInfo, error)
	acceptConsentFn     func(ctx context.Context, challenge string, req *api.AcceptConsentRequest) (*api.RedirectResponse, error)
	rejectConsentFn     func(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error)
}

func (m *mockConsentService) GetLoginRequest(ctx context.Context, challenge string) (*api.LoginRequestInfo, error) {
	if m.getLoginRequestFn != nil {
		return m.getLoginRequestFn(ctx, challenge)
	}
	return &api.LoginRequestInfo{
		Challenge:  challenge,
		ClientID:   "client-1",
		Scope:      "openid profile",
		RequestURL: "https://auth.example.com/oauth/authorize?client_id=client-1",
	}, nil
}

func (m *mockConsentService) AcceptLogin(ctx context.Context, challenge string, req *api.AcceptLoginRequest) (*api.RedirectResponse, error) {
	if m.acceptLoginFn != nil {
		return m.acceptLoginFn(ctx, challenge, req)
	}
	return &api.RedirectResponse{RedirectTo: "https://auth.example.com/consent?challenge=consent-123"}, nil
}

func (m *mockConsentService) RejectLogin(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
	if m.rejectLoginFn != nil {
		return m.rejectLoginFn(ctx, challenge, req)
	}
	return &api.RedirectResponse{RedirectTo: "https://app.example.com/cb?error=access_denied"}, nil
}

func (m *mockConsentService) GetConsentRequest(ctx context.Context, challenge string) (*api.ConsentRequestInfo, error) {
	if m.getConsentRequestFn != nil {
		return m.getConsentRequestFn(ctx, challenge)
	}
	return &api.ConsentRequestInfo{
		Challenge:       challenge,
		ClientID:        "client-1",
		RequestedScopes: []string{"openid", "profile", "email"},
		Subject:         "user-1",
	}, nil
}

func (m *mockConsentService) AcceptConsent(ctx context.Context, challenge string, req *api.AcceptConsentRequest) (*api.RedirectResponse, error) {
	if m.acceptConsentFn != nil {
		return m.acceptConsentFn(ctx, challenge, req)
	}
	return &api.RedirectResponse{RedirectTo: "https://app.example.com/cb?code=auth_code_xyz"}, nil
}

func (m *mockConsentService) RejectConsent(ctx context.Context, challenge string, req *api.RejectRequest) (*api.RedirectResponse, error) {
	if m.rejectConsentFn != nil {
		return m.rejectConsentFn(ctx, challenge, req)
	}
	return &api.RedirectResponse{RedirectTo: "https://app.example.com/cb?error=consent_denied"}, nil
}

// ── Mock Client Approval Service ───────────────────────────────────────────

type mockClientApprovalService struct {
	createThirdPartyClientFn func(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error)
	approveClientFn          func(ctx context.Context, clientID string) (*api.ClientApprovalInfo, error)
}

func (m *mockClientApprovalService) CreateThirdPartyClient(ctx context.Context, req *api.CreateClientRequest) (*api.AdminClientWithSecret, error) {
	if m.createThirdPartyClientFn != nil {
		return m.createThirdPartyClientFn(ctx, req)
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
		ClientSecret: "qf_cs_generated_secret",
	}, nil
}

func (m *mockClientApprovalService) ApproveClient(ctx context.Context, clientID string) (*api.ClientApprovalInfo, error) {
	if m.approveClientFn != nil {
		return m.approveClientFn(ctx, clientID)
	}
	now := time.Now()
	return &api.ClientApprovalInfo{
		ClientID:   clientID,
		ClientName: "test-client",
		Approved:   true,
		ApprovedAt: &now,
		ApprovedBy: "admin-1",
	}, nil
}

// ── Test helpers ───────────────────────────────────────────────────────────

func newAdminConsentRouter(consentSvc api.ConsentService, approvalSvc api.AdminClientApprovalService) *gin.Engine {
	svc := &api.AdminServices{
		Consent:        consentSvc,
		ClientApproval: approvalSvc,
	}
	return api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
}

// ── Login Request Tests ────────────────────────────────────────────────────

func TestAdminGetLoginRequest_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	w := doRequest(r, http.MethodGet, "/admin/oauth/auth/requests/login?login_challenge=abc123", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.LoginRequestInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "abc123", resp.Challenge)
	assert.Equal(t, "client-1", resp.ClientID)
}

func TestAdminGetLoginRequest_MissingChallenge(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	w := doRequest(r, http.MethodGet, "/admin/oauth/auth/requests/login", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminGetLoginRequest_NotFound(t *testing.T) {
	svc := &mockConsentService{
		getLoginRequestFn: func(_ context.Context, _ string) (*api.LoginRequestInfo, error) {
			return nil, api.ErrNotFound
		},
	}
	r := newAdminConsentRouter(svc, nil)

	w := doRequest(r, http.MethodGet, "/admin/oauth/auth/requests/login?login_challenge=bad", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Accept Login Tests ─────────────────────────────────────────────────────

func TestAdminAcceptLogin_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	body := map[string]interface{}{
		"subject":  "user-1",
		"remember": true,
	}
	w := doRequest(r, http.MethodPut, "/admin/oauth/auth/requests/login?login_challenge=abc123&accept=true", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.RedirectTo, "consent")
}

// ── Reject Login Tests ──────���───────────────────────────��──────────────────

func TestAdminRejectLogin_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	body := map[string]interface{}{
		"error":             "access_denied",
		"error_description": "user cancelled",
	}
	w := doRequest(r, http.MethodPut, "/admin/oauth/auth/requests/login?login_challenge=abc123&accept=false", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.RedirectTo, "error=access_denied")
}

// ��─ Consent Request Tests ──────────────────────────────────────────────────

func TestAdminGetConsentRequest_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	w := doRequest(r, http.MethodGet, "/admin/oauth/auth/requests/consent?consent_challenge=consent-123", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.ConsentRequestInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "consent-123", resp.Challenge)
	assert.Equal(t, "user-1", resp.Subject)
	assert.Contains(t, resp.RequestedScopes, "openid")
}

func TestAdminGetConsentRequest_MissingChallenge(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	w := doRequest(r, http.MethodGet, "/admin/oauth/auth/requests/consent", nil)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ── Accept Consent Tests ───────────────────────────────────────────────────

func TestAdminAcceptConsent_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	body := map[string]interface{}{
		"granted_scopes": []string{"openid", "profile"},
		"remember":       true,
	}
	w := doRequest(r, http.MethodPut, "/admin/oauth/auth/requests/consent?consent_challenge=consent-123&accept=true", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.RedirectTo, "code=")
}

// ── Reject Consent Tests ───���────────────────────────────────���──────────────

func TestAdminRejectConsent_Success(t *testing.T) {
	r := newAdminConsentRouter(&mockConsentService{}, nil)

	body := map[string]interface{}{
		"error":             "consent_denied",
		"error_description": "user denied consent",
	}
	w := doRequest(r, http.MethodPut, "/admin/oauth/auth/requests/consent?consent_challenge=consent-123&accept=false", body)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.RedirectResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Contains(t, resp.RedirectTo, "error=consent_denied")
}

// ── Client Approval Tests ──────────────────────────────────────────────────

func TestAdminApproveClient_Success(t *testing.T) {
	r := newAdminConsentRouter(nil, &mockClientApprovalService{})

	w := doRequest(r, http.MethodGet, "/admin/clients/client-1/approve", nil)
	require.Equal(t, http.StatusOK, w.Code)

	var resp api.ClientApprovalInfo
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "client-1", resp.ClientID)
	assert.True(t, resp.Approved)
}

func TestAdminApproveClient_NotFound(t *testing.T) {
	svc := &mockClientApprovalService{
		approveClientFn: func(_ context.Context, _ string) (*api.ClientApprovalInfo, error) {
			return nil, api.ErrNotFound
		},
	}
	r := newAdminConsentRouter(nil, svc)

	w := doRequest(r, http.MethodGet, "/admin/clients/nonexistent/approve", nil)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ── Routes not registered when services are nil ────────────────────────────

func TestAdminConsentRoutes_NotRegisteredWhenNil(t *testing.T) {
	svc := &api.AdminServices{
		// Consent: nil, ClientApproval: nil
	}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})

	tests := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/oauth/auth/requests/login?login_challenge=abc"},
		{http.MethodPut, "/admin/oauth/auth/requests/login?login_challenge=abc&accept=true"},
		{http.MethodGet, "/admin/oauth/auth/requests/consent?consent_challenge=abc"},
		{http.MethodPut, "/admin/oauth/auth/requests/consent?consent_challenge=abc&accept=true"},
		{http.MethodGet, "/admin/clients/c1/approve"},
	}

	for _, tc := range tests {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			w := doRequest(r, tc.method, tc.path, nil)
			// Routes should not exist — 404 or 405
			assert.True(t, w.Code == http.StatusNotFound || w.Code == http.StatusMethodNotAllowed,
				"expected 404/405, got %d for %s %s", w.Code, tc.method, tc.path)
		})
	}
}
