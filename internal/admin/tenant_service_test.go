package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// --- Helpers ---

func testTenant() *domain.Tenant {
	now := time.Now().UTC()
	return &domain.Tenant{
		ID:        uuid.New(),
		Name:      "Test Tenant",
		Slug:      "test-tenant",
		Config:    domain.TenantConfig{},
		Status:    domain.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newTestTenantService(repo *mocks.MockTenantRepository) *TenantService {
	return NewTenantService(repo, zap.NewNop(), audit.NopLogger{})
}

// --- ListTenants ---

func TestTenantService_ListTenants(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		ListFn: func(_ context.Context, limit, offset int) ([]*domain.Tenant, int, error) {
			assert.Equal(t, 20, limit)
			assert.Equal(t, 0, offset)
			return []*domain.Tenant{tenant}, 1, nil
		},
	}
	svc := newTestTenantService(repo)

	result, err := svc.ListTenants(context.Background(), 1, 20)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Tenants, 1)
	assert.Equal(t, tenant.ID.String(), result.Tenants[0].ID)
}

func TestTenantService_ListTenants_Error(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		ListFn: func(_ context.Context, _, _ int) ([]*domain.Tenant, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}
	svc := newTestTenantService(repo)

	_, err := svc.ListTenants(context.Background(), 1, 20)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- GetTenant ---

func TestTenantService_GetTenant(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, id uuid.UUID) (*domain.Tenant, error) {
			assert.Equal(t, tenant.ID, id)
			return tenant, nil
		},
	}
	svc := newTestTenantService(repo)

	result, err := svc.GetTenant(context.Background(), tenant.ID.String())
	require.NoError(t, err)
	assert.Equal(t, tenant.ID.String(), result.ID)
	assert.Equal(t, tenant.Name, result.Name)
}

func TestTenantService_GetTenant_InvalidID(t *testing.T) {
	svc := newTestTenantService(&mocks.MockTenantRepository{})

	_, err := svc.GetTenant(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestTenantService_GetTenant_NotFound(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Tenant, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestTenantService(repo)

	_, err := svc.GetTenant(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- CreateTenant ---

func TestTenantService_CreateTenant(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		CreateFn: func(_ context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
			return tenant, nil
		},
	}
	svc := newTestTenantService(repo)

	req := &api.CreateTenantRequest{
		Name: "My Tenant",
		Slug: "my-tenant",
	}
	result, err := svc.CreateTenant(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "My Tenant", result.Name)
	assert.Equal(t, "my-tenant", result.Slug)
	assert.Equal(t, "active", result.Status)
}

func TestTenantService_CreateTenant_WithConfig(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		CreateFn: func(_ context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
			return tenant, nil
		},
	}
	svc := newTestTenantService(repo)

	minLen := 12
	req := &api.CreateTenantRequest{
		Name: "Configured Tenant",
		Slug: "configured",
		Config: &api.AdminTenantConfig{
			PasswordPolicy: &api.AdminTenantPasswordPolicy{
				MinLength: &minLen,
			},
			MFA: &api.AdminTenantMFAConfig{
				Required:       true,
				AllowedMethods: []string{"totp"},
			},
			AllowedOAuthProviders: []string{"google", "github"},
			TokenTTLs: &api.AdminTenantTokenTTLs{
				AccessTokenTTL:  intPtr(900),
				RefreshTokenTTL: intPtr(86400),
			},
		},
	}
	result, err := svc.CreateTenant(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "Configured Tenant", result.Name)
	require.NotNil(t, result.Config.PasswordPolicy)
	assert.Equal(t, 12, *result.Config.PasswordPolicy.MinLength)
	require.NotNil(t, result.Config.MFA)
	assert.True(t, result.Config.MFA.Required)
	assert.Equal(t, []string{"google", "github"}, result.Config.AllowedOAuthProviders)
	require.NotNil(t, result.Config.TokenTTLs)
	assert.Equal(t, 900, *result.Config.TokenTTLs.AccessTokenTTL)
}

func TestTenantService_CreateTenant_DuplicateSlug(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		CreateFn: func(_ context.Context, _ *domain.Tenant) (*domain.Tenant, error) {
			return nil, fmt.Errorf("slug dup: %w", storage.ErrDuplicateTenant)
		},
	}
	svc := newTestTenantService(repo)

	_, err := svc.CreateTenant(context.Background(), &api.CreateTenantRequest{
		Name: "Dup",
		Slug: "dup",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- UpdateTenant ---

func TestTenantService_UpdateTenant(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, id uuid.UUID) (*domain.Tenant, error) {
			assert.Equal(t, tenant.ID, id)
			return tenant, nil
		},
		UpdateFn: func(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
			return t, nil
		},
	}
	svc := newTestTenantService(repo)

	name := "Updated Name"
	result, err := svc.UpdateTenant(context.Background(), tenant.ID.String(), &api.UpdateTenantRequest{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, "Updated Name", result.Name)
}

func TestTenantService_UpdateTenant_Status(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Tenant, error) {
			return tenant, nil
		},
		UpdateFn: func(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
			return t, nil
		},
	}
	svc := newTestTenantService(repo)

	status := "suspended"
	result, err := svc.UpdateTenant(context.Background(), tenant.ID.String(), &api.UpdateTenantRequest{Status: &status})
	require.NoError(t, err)
	assert.Equal(t, "suspended", result.Status)
}

func TestTenantService_UpdateTenant_InvalidStatus(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Tenant, error) {
			return tenant, nil
		},
	}
	svc := newTestTenantService(repo)

	status := "deleted"
	_, err := svc.UpdateTenant(context.Background(), tenant.ID.String(), &api.UpdateTenantRequest{Status: &status})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestTenantService_UpdateTenant_InvalidID(t *testing.T) {
	svc := newTestTenantService(&mocks.MockTenantRepository{})

	name := "nope"
	_, err := svc.UpdateTenant(context.Background(), "not-a-uuid", &api.UpdateTenantRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestTenantService_UpdateTenant_NotFound(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Tenant, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestTenantService(repo)

	name := "nope"
	_, err := svc.UpdateTenant(context.Background(), uuid.New().String(), &api.UpdateTenantRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- DeleteTenant ---

func TestTenantService_DeleteTenant(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		DeleteFn: func(_ context.Context, _ uuid.UUID) error {
			return nil
		},
	}
	svc := newTestTenantService(repo)

	err := svc.DeleteTenant(context.Background(), uuid.New().String())
	require.NoError(t, err)
}

func TestTenantService_DeleteTenant_NotFound(t *testing.T) {
	repo := &mocks.MockTenantRepository{
		DeleteFn: func(_ context.Context, _ uuid.UUID) error {
			return fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestTenantService(repo)

	err := svc.DeleteTenant(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestTenantService_DeleteTenant_InvalidID(t *testing.T) {
	svc := newTestTenantService(&mocks.MockTenantRepository{})

	err := svc.DeleteTenant(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestTenantService_DeleteTenant_DefaultTenant(t *testing.T) {
	svc := newTestTenantService(&mocks.MockTenantRepository{})

	err := svc.DeleteTenant(context.Background(), domain.DefaultTenantID.String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- Config Validation ---

func TestValidatePasswordPolicy(t *testing.T) {
	tests := []struct {
		name    string
		policy  *api.AdminTenantPasswordPolicy
		wantErr bool
	}{
		{
			name:    "valid policy",
			policy:  &api.AdminTenantPasswordPolicy{MinLength: intPtr(15), MaxLength: intPtr(64)},
			wantErr: false,
		},
		{
			name:    "min_length too small",
			policy:  &api.AdminTenantPasswordPolicy{MinLength: intPtr(4)},
			wantErr: true,
		},
		{
			name:    "max_length exceeds limit",
			policy:  &api.AdminTenantPasswordPolicy{MaxLength: intPtr(200)},
			wantErr: true,
		},
		{
			name:    "max_length less than min_length",
			policy:  &api.AdminTenantPasswordPolicy{MinLength: intPtr(20), MaxLength: intPtr(10)},
			wantErr: true,
		},
		{
			name:    "negative max_age_days",
			policy:  &api.AdminTenantPasswordPolicy{MaxAgeDays: intPtr(-1)},
			wantErr: true,
		},
		{
			name:    "negative history_count",
			policy:  &api.AdminTenantPasswordPolicy{HistoryCount: intPtr(-1)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validatePasswordPolicy(tt.policy)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, api.ErrConflict)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateMFAConfig(t *testing.T) {
	tests := []struct {
		name    string
		mfa     *api.AdminTenantMFAConfig
		wantErr bool
	}{
		{
			name:    "valid config",
			mfa:     &api.AdminTenantMFAConfig{Required: true, AllowedMethods: []string{"totp", "webauthn"}},
			wantErr: false,
		},
		{
			name:    "invalid method",
			mfa:     &api.AdminTenantMFAConfig{AllowedMethods: []string{"sms"}},
			wantErr: true,
		},
		{
			name:    "negative grace period",
			mfa:     &api.AdminTenantMFAConfig{GracePeriodDays: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMFAConfig(tt.mfa)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, api.ErrConflict)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateOAuthProviders(t *testing.T) {
	assert.NoError(t, validateOAuthProviders([]string{"google", "github"}))
	assert.Error(t, validateOAuthProviders([]string{"google", ""}))
}

func TestValidateTokenTTLs(t *testing.T) {
	tests := []struct {
		name    string
		ttls    *api.AdminTenantTokenTTLs
		wantErr bool
	}{
		{
			name:    "valid ttls",
			ttls:    &api.AdminTenantTokenTTLs{AccessTokenTTL: intPtr(900), RefreshTokenTTL: intPtr(86400)},
			wantErr: false,
		},
		{
			name:    "access_token_ttl too low",
			ttls:    &api.AdminTenantTokenTTLs{AccessTokenTTL: intPtr(10)},
			wantErr: true,
		},
		{
			name:    "access_token_ttl too high",
			ttls:    &api.AdminTenantTokenTTLs{AccessTokenTTL: intPtr(maxTokenTTL + 1)},
			wantErr: true,
		},
		{
			name:    "refresh_token_ttl too low",
			ttls:    &api.AdminTenantTokenTTLs{RefreshTokenTTL: intPtr(5)},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateTokenTTLs(tt.ttls)
			if tt.wantErr {
				assert.Error(t, err)
				assert.ErrorIs(t, err, api.ErrConflict)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestTenantService_CreateTenant_InvalidConfig(t *testing.T) {
	repo := &mocks.MockTenantRepository{}
	svc := newTestTenantService(repo)

	_, err := svc.CreateTenant(context.Background(), &api.CreateTenantRequest{
		Name: "Bad Config",
		Slug: "bad-config",
		Config: &api.AdminTenantConfig{
			PasswordPolicy: &api.AdminTenantPasswordPolicy{
				MinLength: intPtr(3),
			},
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestTenantService_UpdateTenant_InvalidConfig(t *testing.T) {
	tenant := testTenant()
	repo := &mocks.MockTenantRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Tenant, error) {
			return tenant, nil
		},
	}
	svc := newTestTenantService(repo)

	_, err := svc.UpdateTenant(context.Background(), tenant.ID.String(), &api.UpdateTenantRequest{
		Config: &api.AdminTenantConfig{
			MFA: &api.AdminTenantMFAConfig{
				AllowedMethods: []string{"sms"},
			},
		},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- domainTenantToAdmin ---

func TestDomainTenantToAdmin(t *testing.T) {
	tenant := testTenant()
	minLen := 15
	tenant.Config = domain.TenantConfig{
		PasswordPolicy: &domain.TenantPasswordPolicy{
			MinLength: &minLen,
		},
		MFA: &domain.TenantMFAConfig{
			Required:       true,
			AllowedMethods: []string{"totp"},
		},
		AllowedOAuthProviders: []string{"google"},
		TokenTTLs: &domain.TenantTokenTTLs{
			AccessTokenTTL:  intPtr(900),
			RefreshTokenTTL: intPtr(86400),
		},
	}

	admin := domainTenantToAdmin(tenant)
	assert.Equal(t, tenant.ID.String(), admin.ID)
	assert.Equal(t, tenant.Name, admin.Name)
	assert.Equal(t, tenant.Slug, admin.Slug)
	assert.Equal(t, string(tenant.Status), admin.Status)
	require.NotNil(t, admin.Config.PasswordPolicy)
	assert.Equal(t, 15, *admin.Config.PasswordPolicy.MinLength)
	require.NotNil(t, admin.Config.MFA)
	assert.True(t, admin.Config.MFA.Required)
	assert.Equal(t, []string{"google"}, admin.Config.AllowedOAuthProviders)
	require.NotNil(t, admin.Config.TokenTTLs)
	assert.Equal(t, 900, *admin.Config.TokenTTLs.AccessTokenTTL)
}

// --- helpers ---

func intPtr(v int) *int { return &v }
