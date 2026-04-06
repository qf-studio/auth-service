package api_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/health"
)

// --- Mock AdminPasswordPolicyService ---

type mockAdminPasswordPolicyService struct {
	listPoliciesFn     func(ctx context.Context, page, perPage int) (*api.AdminPasswordPolicyList, error)
	getPolicyFn        func(ctx context.Context, policyID string) (*api.AdminPasswordPolicy, error)
	createPolicyFn     func(ctx context.Context, req *api.CreatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error)
	updatePolicyFn     func(ctx context.Context, policyID string, req *api.UpdatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error)
	deletePolicyFn     func(ctx context.Context, policyID string) error
	complianceReportFn func(ctx context.Context) (*api.ComplianceReport, error)
}

func (m *mockAdminPasswordPolicyService) ListPolicies(ctx context.Context, page, perPage int) (*api.AdminPasswordPolicyList, error) {
	if m.listPoliciesFn != nil {
		return m.listPoliciesFn(ctx, page, perPage)
	}
	now := time.Now()
	return &api.AdminPasswordPolicyList{
		Policies: []api.AdminPasswordPolicy{{ID: "p1", Name: "default", MinLength: 15, MaxLength: 128, CreatedAt: now, UpdatedAt: now}},
		Total:    1,
		Page:     page,
		PerPage:  perPage,
	}, nil
}

func (m *mockAdminPasswordPolicyService) GetPolicy(ctx context.Context, policyID string) (*api.AdminPasswordPolicy, error) {
	if m.getPolicyFn != nil {
		return m.getPolicyFn(ctx, policyID)
	}
	now := time.Now()
	return &api.AdminPasswordPolicy{ID: policyID, Name: "default", MinLength: 15, MaxLength: 128, CreatedAt: now, UpdatedAt: now}, nil
}

func (m *mockAdminPasswordPolicyService) CreatePolicy(ctx context.Context, req *api.CreatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
	if m.createPolicyFn != nil {
		return m.createPolicyFn(ctx, req)
	}
	now := time.Now()
	minLen := 15
	if req.MinLength != nil {
		minLen = *req.MinLength
	}
	return &api.AdminPasswordPolicy{ID: "new-policy", Name: req.Name, MinLength: minLen, MaxLength: 128, CreatedAt: now, UpdatedAt: now}, nil
}

func (m *mockAdminPasswordPolicyService) UpdatePolicy(ctx context.Context, policyID string, req *api.UpdatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
	if m.updatePolicyFn != nil {
		return m.updatePolicyFn(ctx, policyID, req)
	}
	now := time.Now()
	name := "default"
	if req.Name != nil {
		name = *req.Name
	}
	return &api.AdminPasswordPolicy{ID: policyID, Name: name, MinLength: 15, MaxLength: 128, CreatedAt: now, UpdatedAt: now}, nil
}

func (m *mockAdminPasswordPolicyService) DeletePolicy(ctx context.Context, policyID string) error {
	if m.deletePolicyFn != nil {
		return m.deletePolicyFn(ctx, policyID)
	}
	return nil
}

func (m *mockAdminPasswordPolicyService) ComplianceReport(ctx context.Context) (*api.ComplianceReport, error) {
	if m.complianceReportFn != nil {
		return m.complianceReportFn(ctx)
	}
	return &api.ComplianceReport{
		ExpiredPasswordCount:   0,
		ExpiredPasswordUserIDs: []string{},
		ForceChangeCount:       0,
		ForceChangeUserIDs:     []string{},
		PolicyViolationCount:   0,
	}, nil
}

// --- Helper ---

func newAdminPasswordPolicyRouter(policySvc api.AdminPasswordPolicyService) *api.AdminServices {
	return &api.AdminServices{PasswordPolicies: policySvc}
}

// --- List Policies ---

func TestAdminListPasswordPolicies_Success(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminPasswordPolicyList
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 1, resp.Total)
	assert.Len(t, resp.Policies, 1)
}

func TestAdminListPasswordPolicies_ServiceError(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		listPoliciesFn: func(_ context.Context, _, _ int) (*api.AdminPasswordPolicyList, error) {
			return nil, fmt.Errorf("db down: %w", api.ErrInternalError)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// --- Get Policy ---

func TestAdminGetPasswordPolicy_Success(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies/policy-42", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminPasswordPolicy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "policy-42", resp.ID)
}

func TestAdminGetPasswordPolicy_NotFound(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		getPolicyFn: func(_ context.Context, _ string) (*api.AdminPasswordPolicy, error) {
			return nil, fmt.Errorf("policy not found: %w", api.ErrNotFound)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Create Policy ---

func TestAdminCreatePasswordPolicy_Success(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	body := map[string]interface{}{
		"name":       "strict",
		"min_length": 20,
	}
	w := doRequest(r, http.MethodPost, "/admin/password-policies", body)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp api.AdminPasswordPolicy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "strict", resp.Name)
	assert.Equal(t, 20, resp.MinLength)
}

func TestAdminCreatePasswordPolicy_ValidationError(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	// Missing required name field
	body := map[string]interface{}{"min_length": 20}
	w := doRequest(r, http.MethodPost, "/admin/password-policies", body)

	assert.Equal(t, http.StatusUnprocessableEntity, w.Code)
}

func TestAdminCreatePasswordPolicy_InvalidJSON(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodPost, "/admin/password-policies", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAdminCreatePasswordPolicy_Conflict(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		createPolicyFn: func(_ context.Context, _ *api.CreatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
			return nil, fmt.Errorf("name already exists: %w", api.ErrConflict)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	body := map[string]interface{}{"name": "dup"}
	w := doRequest(r, http.MethodPost, "/admin/password-policies", body)

	assert.Equal(t, http.StatusConflict, w.Code)
}

// --- Update Policy ---

func TestAdminUpdatePasswordPolicy_Success(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	body := map[string]interface{}{"name": "updated"}
	w := doRequest(r, http.MethodPut, "/admin/password-policies/policy-42", body)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.AdminPasswordPolicy
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "updated", resp.Name)
}

func TestAdminUpdatePasswordPolicy_NotFound(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		updatePolicyFn: func(_ context.Context, _ string, _ *api.UpdatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
			return nil, fmt.Errorf("policy not found: %w", api.ErrNotFound)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	body := map[string]interface{}{"name": "nope"}
	w := doRequest(r, http.MethodPut, "/admin/password-policies/nonexistent", body)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestAdminUpdatePasswordPolicy_InvalidJSON(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodPut, "/admin/password-policies/policy-42", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// --- Delete Policy ---

func TestAdminDeletePasswordPolicy_Success(t *testing.T) {
	svc := &api.AdminServices{PasswordPolicies: &mockAdminPasswordPolicyService{}}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodDelete, "/admin/password-policies/policy-42", nil)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestAdminDeletePasswordPolicy_NotFound(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		deletePolicyFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("policy not found: %w", api.ErrNotFound)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodDelete, "/admin/password-policies/nonexistent", nil)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// --- Compliance Report ---

func TestAdminPasswordPolicyCompliance_Success(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		complianceReportFn: func(_ context.Context) (*api.ComplianceReport, error) {
			return &api.ComplianceReport{
				ExpiredPasswordCount:   2,
				ExpiredPasswordUserIDs: []string{"user-1", "user-2"},
				ForceChangeCount:       1,
				ForceChangeUserIDs:     []string{"user-3"},
				PolicyViolationCount:   3,
			}, nil
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies/compliance", nil)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp api.ComplianceReport
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, 2, resp.ExpiredPasswordCount)
	assert.Equal(t, []string{"user-1", "user-2"}, resp.ExpiredPasswordUserIDs)
	assert.Equal(t, 1, resp.ForceChangeCount)
	assert.Equal(t, 3, resp.PolicyViolationCount)
}

func TestAdminPasswordPolicyCompliance_Error(t *testing.T) {
	mock := &mockAdminPasswordPolicyService{
		complianceReportFn: func(_ context.Context) (*api.ComplianceReport, error) {
			return nil, fmt.Errorf("db error: %w", api.ErrInternalError)
		},
	}
	svc := &api.AdminServices{PasswordPolicies: mock}
	r := api.NewAdminRouter(svc, &api.AdminDeps{Health: health.NewService()})
	w := doRequest(r, http.MethodGet, "/admin/password-policies/compliance", nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
