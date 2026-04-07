package tenant_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/tenant"
)

// mockTenantRepo implements storage.TenantRepository for testing.
type mockTenantRepo struct {
	byID   map[uuid.UUID]*domain.Tenant
	bySlug map[string]*domain.Tenant
}

func (m *mockTenantRepo) Create(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	return t, nil
}

func (m *mockTenantRepo) FindByID(_ context.Context, id uuid.UUID) (*domain.Tenant, error) {
	t, ok := m.byID[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return t, nil
}

func (m *mockTenantRepo) FindBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	t, ok := m.bySlug[slug]
	if !ok {
		return nil, storage.ErrNotFound
	}
	return t, nil
}

func (m *mockTenantRepo) List(_ context.Context, _, _ int, _ string) ([]*domain.Tenant, int, error) {
	return nil, 0, nil
}

func (m *mockTenantRepo) Update(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	return t, nil
}

func (m *mockTenantRepo) Delete(_ context.Context, _ uuid.UUID) error {
	return nil
}

func TestResolver_ResolveTenantByUUID(t *testing.T) {
	id := uuid.New()
	repo := &mockTenantRepo{
		byID: map[uuid.UUID]*domain.Tenant{
			id: {ID: id, Name: "Test Tenant", Slug: "test", Status: domain.TenantStatusActive},
		},
		bySlug: map[string]*domain.Tenant{},
	}

	r := tenant.NewResolver(repo)
	cfg, err := r.ResolveTenant(context.Background(), id.String())

	require.NoError(t, err)
	assert.Equal(t, id.String(), cfg.TenantID)
	assert.Equal(t, "Test Tenant", cfg.Name)
	assert.True(t, cfg.Active)
}

func TestResolver_ResolveTenantBySlug(t *testing.T) {
	id := uuid.New()
	repo := &mockTenantRepo{
		byID: map[uuid.UUID]*domain.Tenant{},
		bySlug: map[string]*domain.Tenant{
			"acme": {ID: id, Name: "Acme Corp", Slug: "acme", Status: domain.TenantStatusActive},
		},
	}

	r := tenant.NewResolver(repo)
	cfg, err := r.ResolveTenant(context.Background(), "acme")

	require.NoError(t, err)
	assert.Equal(t, id.String(), cfg.TenantID)
	assert.Equal(t, "Acme Corp", cfg.Name)
	assert.True(t, cfg.Active)
}

func TestResolver_ResolveTenantInactive(t *testing.T) {
	id := uuid.New()
	repo := &mockTenantRepo{
		byID: map[uuid.UUID]*domain.Tenant{},
		bySlug: map[string]*domain.Tenant{
			"suspended": {ID: id, Name: "Suspended", Slug: "suspended", Status: domain.TenantStatusSuspended},
		},
	}

	r := tenant.NewResolver(repo)
	cfg, err := r.ResolveTenant(context.Background(), "suspended")

	require.NoError(t, err)
	assert.False(t, cfg.Active)
}

func TestResolver_ResolveTenantNotFound(t *testing.T) {
	repo := &mockTenantRepo{
		byID:   map[uuid.UUID]*domain.Tenant{},
		bySlug: map[string]*domain.Tenant{},
	}

	r := tenant.NewResolver(repo)
	_, err := r.ResolveTenant(context.Background(), "nonexistent")

	require.Error(t, err)
	assert.True(t, errors.Is(err, storage.ErrNotFound))
}
