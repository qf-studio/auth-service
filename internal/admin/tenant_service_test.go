package admin_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

// stubTenantRepo is a minimal in-memory stub for testing TenantService.
type stubTenantRepo struct {
	byID   map[uuid.UUID]*domain.Tenant
	bySlug map[string]*domain.Tenant
	err    error
}

func newStubTenantRepo(tenants ...*domain.Tenant) *stubTenantRepo {
	r := &stubTenantRepo{
		byID:   make(map[uuid.UUID]*domain.Tenant),
		bySlug: make(map[string]*domain.Tenant),
	}
	for _, t := range tenants {
		r.byID[t.ID] = t
		r.bySlug[t.Slug] = t
	}
	return r
}

func (r *stubTenantRepo) Create(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.byID[t.ID] = t
	return t, nil
}

func (r *stubTenantRepo) FindByID(_ context.Context, id uuid.UUID) (*domain.Tenant, error) {
	if r.err != nil {
		return nil, r.err
	}
	t, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *stubTenantRepo) FindBySlug(_ context.Context, slug string) (*domain.Tenant, error) {
	if r.err != nil {
		return nil, r.err
	}
	t, ok := r.bySlug[slug]
	if !ok {
		return nil, errors.New("not found")
	}
	return t, nil
}

func (r *stubTenantRepo) List(_ context.Context, limit, offset int) ([]*domain.Tenant, int, error) {
	if r.err != nil {
		return nil, 0, r.err
	}
	all := make([]*domain.Tenant, 0, len(r.byID))
	for _, t := range r.byID {
		all = append(all, t)
	}
	return all, len(all), nil
}

func (r *stubTenantRepo) Update(_ context.Context, t *domain.Tenant) (*domain.Tenant, error) {
	if r.err != nil {
		return nil, r.err
	}
	r.byID[t.ID] = t
	return t, nil
}

func (r *stubTenantRepo) Delete(_ context.Context, id uuid.UUID) error {
	if r.err != nil {
		return r.err
	}
	delete(r.byID, id)
	return nil
}

// noopAudit discards all audit events.
type noopAudit struct{}

func (n *noopAudit) LogEvent(_ context.Context, _ audit.Event) {}

func newTenantSvc(repo *stubTenantRepo) *admin.TenantService {
	return admin.NewTenantService(repo, zap.NewNop(), &noopAudit{})
}

func TestTenantService_GetTenant(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Acme", Slug: "acme", Status: domain.TenantStatusActive}
	svc := newTenantSvc(newStubTenantRepo(tenant))

	t.Run("found", func(t *testing.T) {
		got, err := svc.GetTenant(context.Background(), id.String())
		require.NoError(t, err)
		assert.Equal(t, id, got.ID)
	})

	t.Run("invalid uuid", func(t *testing.T) {
		_, err := svc.GetTenant(context.Background(), "not-a-uuid")
		require.Error(t, err)
	})

	t.Run("not found", func(t *testing.T) {
		_, err := svc.GetTenant(context.Background(), uuid.NewString())
		require.Error(t, err)
	})
}

func TestTenantService_CreateTenant(t *testing.T) {
	repo := newStubTenantRepo()
	svc := newTenantSvc(repo)

	tenant := &domain.Tenant{ID: uuid.New(), Name: "Beta", Slug: "beta", Status: domain.TenantStatusActive}
	got, err := svc.CreateTenant(context.Background(), tenant)
	require.NoError(t, err)
	assert.Equal(t, tenant.ID, got.ID)
}

func TestTenantService_DeleteTenant(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Del", Slug: "del", Status: domain.TenantStatusActive}
	svc := newTenantSvc(newStubTenantRepo(tenant))

	err := svc.DeleteTenant(context.Background(), id.String())
	require.NoError(t, err)

	// Verify deleted.
	_, err = svc.GetTenant(context.Background(), id.String())
	require.Error(t, err)
}

func TestTenantService_ListTenants(t *testing.T) {
	id := uuid.New()
	tenant := &domain.Tenant{ID: id, Name: "Gamma", Slug: "gamma", Status: domain.TenantStatusActive}
	svc := newTenantSvc(newStubTenantRepo(tenant))

	tenants, total, err := svc.ListTenants(context.Background(), 1, 10)
	require.NoError(t, err)
	assert.Equal(t, 1, total)
	assert.Len(t, tenants, 1)
}
