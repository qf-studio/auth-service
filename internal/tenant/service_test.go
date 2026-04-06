package tenant

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// mockTenantRepo is a package-private mock for testing.
type mockTenantRepo struct {
	createFn     func(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	findByIDFn   func(ctx context.Context, id string) (*domain.Tenant, error)
	findBySlugFn func(ctx context.Context, slug string) (*domain.Tenant, error)
	listFn       func(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.Tenant, int, error)
	updateFn     func(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error)
	deleteFn     func(ctx context.Context, id string) error
}

func (m *mockTenantRepo) Create(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	if m.createFn != nil {
		return m.createFn(ctx, tenant)
	}
	return tenant, nil
}

func (m *mockTenantRepo) FindByID(ctx context.Context, id string) (*domain.Tenant, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}

func (m *mockTenantRepo) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	if m.findBySlugFn != nil {
		return m.findBySlugFn(ctx, slug)
	}
	return nil, storage.ErrNotFound
}

func (m *mockTenantRepo) List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.Tenant, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, limit, offset, includeDeleted)
	}
	return nil, 0, nil
}

func (m *mockTenantRepo) Update(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, tenant)
	}
	return tenant, nil
}

func (m *mockTenantRepo) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func testCfg() config.TenantConfig {
	return config.TenantConfig{
		SlugMinLength: 2,
		SlugMaxLength: 63,
		NameMaxLength: 128,
	}
}

func testService(repo *mockTenantRepo) *Service {
	return NewService(repo, zap.NewNop(), testCfg())
}

func TestCreate(t *testing.T) {
	tests := []struct {
		name    string
		slug    string
		tName   string
		setup   func(repo *mockTenantRepo)
		wantErr string
	}{
		{
			name:  "success",
			slug:  "acme",
			tName: "Acme Corp",
			setup: func(repo *mockTenantRepo) {
				repo.createFn = func(_ context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
					return tenant, nil
				}
			},
		},
		{
			name:    "slug too short",
			slug:    "a",
			tName:   "Acme Corp",
			wantErr: "slug must be at least 2 characters",
		},
		{
			name:    "slug invalid characters",
			slug:    "ACME_Corp",
			tName:   "Acme Corp",
			wantErr: "slug must be lowercase alphanumeric",
		},
		{
			name:    "slug starts with hyphen",
			slug:    "-acme",
			tName:   "Acme Corp",
			wantErr: "slug must be lowercase alphanumeric",
		},
		{
			name:    "slug ends with hyphen",
			slug:    "acme-",
			tName:   "Acme Corp",
			wantErr: "slug must be lowercase alphanumeric",
		},
		{
			name:    "empty name",
			slug:    "acme",
			tName:   "",
			wantErr: "name is required",
		},
		{
			name:  "duplicate slug",
			slug:  "acme",
			tName: "Acme Corp",
			setup: func(repo *mockTenantRepo) {
				repo.createFn = func(_ context.Context, _ *domain.Tenant) (*domain.Tenant, error) {
					return nil, fmt.Errorf("tenant slug acme: %w", storage.ErrDuplicateTenantSlug)
				}
			},
			wantErr: "duplicate tenant slug",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			result, err := svc.Create(context.Background(), tt.slug, tt.tName)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
				assert.Equal(t, tt.slug, result.Slug)
				assert.Equal(t, tt.tName, result.Name)
				assert.True(t, result.Active)
				assert.Contains(t, result.ID, "tnt_")
			}
		})
	}
}

func TestFindByID(t *testing.T) {
	now := time.Now().UTC()
	tenant := &domain.Tenant{ID: "tnt_abc123", Slug: "acme", Name: "Acme", Active: true, CreatedAt: now, UpdatedAt: now}

	tests := []struct {
		name    string
		id      string
		setup   func(repo *mockTenantRepo)
		wantErr string
	}{
		{
			name: "found",
			id:   "tnt_abc123",
			setup: func(repo *mockTenantRepo) {
				repo.findByIDFn = func(_ context.Context, _ string) (*domain.Tenant, error) {
					return tenant, nil
				}
			},
		},
		{
			name:    "not found",
			id:      "tnt_nonexistent",
			wantErr: "tenant not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			result, err := svc.FindByID(context.Background(), tt.id)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tenant.ID, result.ID)
			}
		})
	}
}

func TestFindBySlug(t *testing.T) {
	now := time.Now().UTC()
	tenant := &domain.Tenant{ID: "tnt_abc123", Slug: "acme", Name: "Acme", Active: true, CreatedAt: now, UpdatedAt: now}

	tests := []struct {
		name    string
		slug    string
		setup   func(repo *mockTenantRepo)
		wantErr string
	}{
		{
			name: "found",
			slug: "acme",
			setup: func(repo *mockTenantRepo) {
				repo.findBySlugFn = func(_ context.Context, _ string) (*domain.Tenant, error) {
					return tenant, nil
				}
			},
		},
		{
			name:    "not found",
			slug:    "nonexistent",
			wantErr: "tenant not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			result, err := svc.FindBySlug(context.Background(), tt.slug)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tenant.ID, result.ID)
			}
		})
	}
}

func TestList(t *testing.T) {
	tests := []struct {
		name       string
		limit      int
		offset     int
		wantLimit  int
		wantOffset int
	}{
		{name: "defaults", limit: 0, offset: -1, wantLimit: 20, wantOffset: 0},
		{name: "clamped max", limit: 200, offset: 0, wantLimit: 100, wantOffset: 0},
		{name: "normal", limit: 10, offset: 5, wantLimit: 10, wantOffset: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{
				listFn: func(_ context.Context, limit, offset int, _ bool) ([]*domain.Tenant, int, error) {
					assert.Equal(t, tt.wantLimit, limit)
					assert.Equal(t, tt.wantOffset, offset)
					return nil, 0, nil
				},
			}
			svc := testService(repo)
			_, _, err := svc.List(context.Background(), tt.limit, tt.offset, false)
			require.NoError(t, err)
		})
	}
}

func TestUpdate(t *testing.T) {
	now := time.Now().UTC()
	existing := &domain.Tenant{ID: "tnt_abc", Slug: "acme", Name: "Acme", Active: true, CreatedAt: now, UpdatedAt: now}
	active := true

	tests := []struct {
		name    string
		id      string
		slug    string
		tName   string
		active  *bool
		setup   func(repo *mockTenantRepo)
		wantErr string
	}{
		{
			name:   "success",
			id:     "tnt_abc",
			slug:   "new-slug",
			tName:  "New Name",
			active: &active,
			setup: func(repo *mockTenantRepo) {
				repo.findByIDFn = func(_ context.Context, _ string) (*domain.Tenant, error) {
					cp := *existing
					return &cp, nil
				}
				repo.updateFn = func(_ context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
					return tenant, nil
				}
			},
		},
		{
			name:    "not found",
			id:      "tnt_nope",
			slug:    "slug",
			wantErr: "tenant not found",
		},
		{
			name:  "invalid slug",
			id:    "tnt_abc",
			slug:  "has_underscore",
			tName: "Name",
			setup: func(repo *mockTenantRepo) {
				repo.findByIDFn = func(_ context.Context, _ string) (*domain.Tenant, error) {
					cp := *existing
					return &cp, nil
				}
			},
			wantErr: "slug must be lowercase alphanumeric",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			result, err := svc.Update(context.Background(), tt.id, tt.slug, tt.tName, tt.active)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

func TestDelete(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		setup   func(repo *mockTenantRepo)
		wantErr string
	}{
		{
			name: "success",
			id:   "tnt_abc",
		},
		{
			name: "not found",
			id:   "tnt_nope",
			setup: func(repo *mockTenantRepo) {
				repo.deleteFn = func(_ context.Context, _ string) error {
					return fmt.Errorf("tenant tnt_nope: %w", storage.ErrNotFound)
				}
			},
			wantErr: "tenant not found",
		},
		{
			name: "already deleted",
			id:   "tnt_old",
			setup: func(repo *mockTenantRepo) {
				repo.deleteFn = func(_ context.Context, _ string) error {
					return fmt.Errorf("tenant tnt_old: %w", storage.ErrAlreadyDeleted)
				}
			},
			wantErr: "already deleted",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			err := svc.Delete(context.Background(), tt.id)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestResolveTenant(t *testing.T) {
	now := time.Now().UTC()
	activeTenant := &domain.Tenant{ID: "tnt_abc", Slug: "acme", Name: "Acme", Active: true, CreatedAt: now, UpdatedAt: now}
	inactiveTenant := &domain.Tenant{ID: "tnt_def", Slug: "dead", Name: "Dead Co", Active: false, CreatedAt: now, UpdatedAt: now}

	tests := []struct {
		name       string
		identifier string
		setup      func(repo *mockTenantRepo)
		wantActive bool
		wantErr    string
	}{
		{
			name:       "resolve by ID",
			identifier: "tnt_abc",
			setup: func(repo *mockTenantRepo) {
				repo.findByIDFn = func(_ context.Context, id string) (*domain.Tenant, error) {
					if id == "tnt_abc" {
						return activeTenant, nil
					}
					return nil, storage.ErrNotFound
				}
			},
			wantActive: true,
		},
		{
			name:       "resolve by slug",
			identifier: "acme",
			setup: func(repo *mockTenantRepo) {
				repo.findBySlugFn = func(_ context.Context, slug string) (*domain.Tenant, error) {
					if slug == "acme" {
						return activeTenant, nil
					}
					return nil, storage.ErrNotFound
				}
			},
			wantActive: true,
		},
		{
			name:       "resolve inactive tenant",
			identifier: "tnt_def",
			setup: func(repo *mockTenantRepo) {
				repo.findByIDFn = func(_ context.Context, _ string) (*domain.Tenant, error) {
					return inactiveTenant, nil
				}
			},
			wantActive: false,
		},
		{
			name:       "tenant not found",
			identifier: "nonexistent",
			wantErr:    "tenant not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockTenantRepo{}
			if tt.setup != nil {
				tt.setup(repo)
			}
			svc := testService(repo)

			cfg, err := svc.ResolveTenant(context.Background(), tt.identifier)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, cfg)
				assert.Equal(t, tt.wantActive, cfg.Active)
			}
		})
	}
}

func TestValidateSlug(t *testing.T) {
	svc := testService(&mockTenantRepo{})

	tests := []struct {
		slug    string
		wantErr bool
	}{
		{"ab", false},
		{"a", true},                    // too short
		{"my-tenant", false},           // valid with hyphen
		{"my--tenant", false},          // double hyphen is valid
		{"-tenant", true},              // starts with hyphen
		{"tenant-", true},              // ends with hyphen
		{"UPPER", true},                // uppercase
		{"has_underscore", true},       // underscore
		{"has space", true},            // space
		{"a2", false},                  // min length
		{"x", true},                    // below min
	}

	for _, tt := range tests {
		t.Run(tt.slug, func(t *testing.T) {
			err := svc.validateSlug(tt.slug)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
