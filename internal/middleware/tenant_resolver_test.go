package middleware_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// stubRepoForResolver is a minimal stub for storage.TenantRepository.
type stubRepoForResolver struct {
	byID   map[uuid.UUID]*domain.Tenant
	bySlug map[string]*domain.Tenant
}

func newStubRepoForResolver(tenants ...*domain.Tenant) *stubRepoForResolver {
	r := &stubRepoForResolver{
		byID:   make(map[uuid.UUID]*domain.Tenant),
		bySlug: make(map[string]*domain.Tenant),
	}
	for _, t := range tenants {
		r.byID[t.ID] = t
		r.bySlug[t.Slug] = t
	}
	return r
}

func (r *stubRepoForResolver) Create(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	return t, nil
}

func (r *stubRepoForResolver) FindByID(_ context.Context, id uuid.UUID) (*domain.Tenant, error) {
	t, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *stubRepoForResolver) FindBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	t, ok := r.bySlug[slug]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *stubRepoForResolver) List(_ context.Context, _, _ int) ([]*domain.Tenant, int, error) {
	return nil, 0, nil
}

func (r *stubRepoForResolver) Update(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	return t, nil
}

func (r *stubRepoForResolver) Delete(_ context.Context, _ uuid.UUID) error {
	return nil
}

func TestTenantRepositoryResolver_ByUUID(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Acme", Slug: "acme", Status: domain.TenantStatusActive}
	resolver := middleware.NewTenantRepositoryResolver(newStubRepoForResolver(tenant))

	cfg, err := resolver.ResolveTenant(context.Background(), id.String())
	require.NoError(t, err)
	assert.Equal(t, id.String(), cfg.TenantID)
	assert.True(t, cfg.Active)
}

func TestTenantRepositoryResolver_BySlug(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Acme", Slug: "acme", Status: domain.TenantStatusActive}
	resolver := middleware.NewTenantRepositoryResolver(newStubRepoForResolver(tenant))

	cfg, err := resolver.ResolveTenant(context.Background(), "acme")
	require.NoError(t, err)
	assert.Equal(t, id.String(), cfg.TenantID)
	assert.Equal(t, "Acme", cfg.Name)
}

func TestTenantRepositoryResolver_NotFound(t *testing.T) {
	resolver := middleware.NewTenantRepositoryResolver(newStubRepoForResolver())

	_, err := resolver.ResolveTenant(context.Background(), "unknown-slug")
	require.Error(t, err)
}

func TestTenantRepositoryResolver_Inactive(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Suspended", Slug: "susp", Status: domain.TenantStatusSuspended}
	resolver := middleware.NewTenantRepositoryResolver(newStubRepoForResolver(tenant))

	cfg, err := resolver.ResolveTenant(context.Background(), id.String())
	require.NoError(t, err)
	assert.False(t, cfg.Active)
}
