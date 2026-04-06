package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock PasswordPolicyRepository ---

type mockPasswordPolicyRepo struct {
	listFn             func(ctx context.Context, limit, offset int) ([]*domain.PasswordPolicy, int, error)
	findByIDFn         func(ctx context.Context, id string) (*domain.PasswordPolicy, error)
	createFn           func(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error)
	updateFn           func(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error)
	softDeleteFn       func(ctx context.Context, id string) error
	complianceReportFn func(ctx context.Context) (*storage.ComplianceData, error)
}

func (m *mockPasswordPolicyRepo) List(ctx context.Context, limit, offset int) ([]*domain.PasswordPolicy, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, limit, offset)
	}
	return []*domain.PasswordPolicy{testPolicy()}, 1, nil
}

func (m *mockPasswordPolicyRepo) FindByID(ctx context.Context, id string) (*domain.PasswordPolicy, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	p := testPolicy()
	p.ID = id
	return p, nil
}

func (m *mockPasswordPolicyRepo) Create(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
	if m.createFn != nil {
		return m.createFn(ctx, policy)
	}
	return policy, nil
}

func (m *mockPasswordPolicyRepo) Update(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, policy)
	}
	return policy, nil
}

func (m *mockPasswordPolicyRepo) SoftDelete(ctx context.Context, id string) error {
	if m.softDeleteFn != nil {
		return m.softDeleteFn(ctx, id)
	}
	return nil
}

func (m *mockPasswordPolicyRepo) ComplianceReport(ctx context.Context) (*storage.ComplianceData, error) {
	if m.complianceReportFn != nil {
		return m.complianceReportFn(ctx)
	}
	return &storage.ComplianceData{}, nil
}

// --- Helpers ---

func testPolicy() *domain.PasswordPolicy {
	now := time.Now()
	return &domain.PasswordPolicy{
		ID:           "policy-1",
		Name:         "default",
		MinLength:    15,
		MaxLength:    128,
		MaxAgeDays:   90,
		HistoryCount: 5,
		RequireMFA:   false,
		IsDefault:    true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
}

func newTestPolicyService(repo *mockPasswordPolicyRepo) *PasswordPolicyService {
	return NewPasswordPolicyService(repo, zap.NewNop(), audit.NopLogger{})
}

// --- ListPolicies ---

func TestPasswordPolicyService_ListPolicies(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		listFn: func(_ context.Context, limit, offset int) ([]*domain.PasswordPolicy, int, error) {
			assert.Equal(t, 20, limit)
			assert.Equal(t, 0, offset)
			return []*domain.PasswordPolicy{testPolicy()}, 1, nil
		},
	}
	svc := newTestPolicyService(repo)

	result, err := svc.ListPolicies(context.Background(), 1, 20)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Policies, 1)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PerPage)
}

func TestPasswordPolicyService_ListPolicies_Error(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		listFn: func(_ context.Context, _, _ int) ([]*domain.PasswordPolicy, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}
	svc := newTestPolicyService(repo)

	_, err := svc.ListPolicies(context.Background(), 1, 20)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- GetPolicy ---

func TestPasswordPolicyService_GetPolicy(t *testing.T) {
	svc := newTestPolicyService(&mockPasswordPolicyRepo{})

	policy, err := svc.GetPolicy(context.Background(), "policy-42")
	require.NoError(t, err)
	assert.Equal(t, "policy-42", policy.ID)
}

func TestPasswordPolicyService_GetPolicy_NotFound(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.PasswordPolicy, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestPolicyService(repo)

	_, err := svc.GetPolicy(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- CreatePolicy ---

func TestPasswordPolicyService_CreatePolicy(t *testing.T) {
	svc := newTestPolicyService(&mockPasswordPolicyRepo{})

	minLen := 20
	req := &api.CreatePasswordPolicyRequest{
		Name:      "strict",
		MinLength: &minLen,
	}
	policy, err := svc.CreatePolicy(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "strict", policy.Name)
	assert.Equal(t, 20, policy.MinLength)
	assert.Equal(t, 128, policy.MaxLength) // default
}

func TestPasswordPolicyService_CreatePolicy_Defaults(t *testing.T) {
	svc := newTestPolicyService(&mockPasswordPolicyRepo{})

	req := &api.CreatePasswordPolicyRequest{Name: "minimal"}
	policy, err := svc.CreatePolicy(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, 15, policy.MinLength)
	assert.Equal(t, 128, policy.MaxLength)
	assert.Equal(t, 0, policy.MaxAgeDays)
	assert.Equal(t, 0, policy.HistoryCount)
	assert.False(t, policy.RequireMFA)
	assert.False(t, policy.IsDefault)
}

func TestPasswordPolicyService_CreatePolicy_DuplicateName(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		createFn: func(_ context.Context, _ *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
			return nil, fmt.Errorf("dup: %w", storage.ErrDuplicatePolicyName)
		},
	}
	svc := newTestPolicyService(repo)

	_, err := svc.CreatePolicy(context.Background(), &api.CreatePasswordPolicyRequest{Name: "dup"})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- UpdatePolicy ---

func TestPasswordPolicyService_UpdatePolicy(t *testing.T) {
	svc := newTestPolicyService(&mockPasswordPolicyRepo{})

	name := "updated-name"
	policy, err := svc.UpdatePolicy(context.Background(), "policy-1", &api.UpdatePasswordPolicyRequest{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, "updated-name", policy.Name)
}

func TestPasswordPolicyService_UpdatePolicy_NotFound(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.PasswordPolicy, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestPolicyService(repo)

	name := "nope"
	_, err := svc.UpdatePolicy(context.Background(), "nonexistent", &api.UpdatePasswordPolicyRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestPasswordPolicyService_UpdatePolicy_DuplicateName(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		updateFn: func(_ context.Context, _ *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
			return nil, fmt.Errorf("dup: %w", storage.ErrDuplicatePolicyName)
		},
	}
	svc := newTestPolicyService(repo)

	name := "existing"
	_, err := svc.UpdatePolicy(context.Background(), "policy-1", &api.UpdatePasswordPolicyRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- DeletePolicy ---

func TestPasswordPolicyService_DeletePolicy(t *testing.T) {
	svc := newTestPolicyService(&mockPasswordPolicyRepo{})

	err := svc.DeletePolicy(context.Background(), "policy-1")
	require.NoError(t, err)
}

func TestPasswordPolicyService_DeletePolicy_NotFound(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		softDeleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestPolicyService(repo)

	err := svc.DeletePolicy(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestPasswordPolicyService_DeletePolicy_AlreadyDeleted(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		softDeleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("already deleted: %w", storage.ErrAlreadyDeleted)
		},
	}
	svc := newTestPolicyService(repo)

	err := svc.DeletePolicy(context.Background(), "deleted-policy")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- ComplianceReport ---

func TestPasswordPolicyService_ComplianceReport(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		complianceReportFn: func(_ context.Context) (*storage.ComplianceData, error) {
			return &storage.ComplianceData{
				ExpiredPasswordCount:   2,
				ExpiredPasswordUserIDs: []string{"user-1", "user-2"},
				ForceChangeCount:       1,
				ForceChangeUserIDs:     []string{"user-3"},
				PolicyViolationCount:   3,
			}, nil
		},
	}
	svc := newTestPolicyService(repo)

	report, err := svc.ComplianceReport(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 2, report.ExpiredPasswordCount)
	assert.Equal(t, []string{"user-1", "user-2"}, report.ExpiredPasswordUserIDs)
	assert.Equal(t, 1, report.ForceChangeCount)
	assert.Equal(t, []string{"user-3"}, report.ForceChangeUserIDs)
	assert.Equal(t, 3, report.PolicyViolationCount)
}

func TestPasswordPolicyService_ComplianceReport_NilSlices(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		complianceReportFn: func(_ context.Context) (*storage.ComplianceData, error) {
			return &storage.ComplianceData{}, nil
		},
	}
	svc := newTestPolicyService(repo)

	report, err := svc.ComplianceReport(context.Background())
	require.NoError(t, err)
	assert.NotNil(t, report.ExpiredPasswordUserIDs)
	assert.NotNil(t, report.ForceChangeUserIDs)
	assert.Empty(t, report.ExpiredPasswordUserIDs)
	assert.Empty(t, report.ForceChangeUserIDs)
}

func TestPasswordPolicyService_ComplianceReport_Error(t *testing.T) {
	repo := &mockPasswordPolicyRepo{
		complianceReportFn: func(_ context.Context) (*storage.ComplianceData, error) {
			return nil, fmt.Errorf("db error")
		},
	}
	svc := newTestPolicyService(repo)

	_, err := svc.ComplianceReport(context.Background())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- domainPolicyToAdmin ---

func TestDomainPolicyToAdmin(t *testing.T) {
	now := time.Now()
	p := &domain.PasswordPolicy{
		ID:           "policy-1",
		Name:         "strict",
		MinLength:    20,
		MaxLength:    256,
		MaxAgeDays:   90,
		HistoryCount: 10,
		RequireMFA:   true,
		IsDefault:    true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	admin := domainPolicyToAdmin(p)
	assert.Equal(t, "policy-1", admin.ID)
	assert.Equal(t, "strict", admin.Name)
	assert.Equal(t, 20, admin.MinLength)
	assert.Equal(t, 256, admin.MaxLength)
	assert.Equal(t, 90, admin.MaxAgeDays)
	assert.Equal(t, 10, admin.HistoryCount)
	assert.True(t, admin.RequireMFA)
	assert.True(t, admin.IsDefault)
}
