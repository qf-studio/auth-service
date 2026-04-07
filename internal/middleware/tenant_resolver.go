package middleware

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// TenantRepositoryResolver adapts a storage.TenantRepository to the TenantResolver
// interface used by TenantMiddleware. It resolves tenants by UUID or slug.
type TenantRepositoryResolver struct {
	repo storage.TenantRepository
}

// NewTenantRepositoryResolver creates a TenantResolver backed by the tenant repository.
func NewTenantRepositoryResolver(repo storage.TenantRepository) *TenantRepositoryResolver {
	return &TenantRepositoryResolver{repo: repo}
}

// ResolveTenant looks up a tenant by UUID string or slug. It tries UUID parse first;
// if that fails it falls back to slug lookup.
func (r *TenantRepositoryResolver) ResolveTenant(ctx context.Context, identifier string) (*TenantConfig, error) {
	var tenant *domain.Tenant
	var err error

	if parsed, parseErr := uuid.Parse(identifier); parseErr == nil {
		tenant, err = r.repo.FindByID(ctx, parsed)
	} else {
		tenant, err = r.repo.FindBySlug(ctx, identifier)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve tenant %q: %w", identifier, err)
	}

	return &TenantConfig{
		TenantID: tenant.ID.String(),
		Name:     tenant.Name,
		Active:   tenant.IsActive(),
	}, nil
}
