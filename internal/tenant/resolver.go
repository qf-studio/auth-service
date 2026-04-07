// Package tenant implements tenant resolution for the multi-tenancy middleware.
package tenant

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Resolver implements middleware.TenantResolver by looking up tenants
// from the database via TenantRepository.
type Resolver struct {
	repo storage.TenantRepository
}

// NewResolver creates a new Resolver backed by the given TenantRepository.
func NewResolver(repo storage.TenantRepository) *Resolver {
	return &Resolver{repo: repo}
}

// ResolveTenant looks up a tenant by identifier (UUID or slug).
// Returns a middleware.TenantConfig suitable for caching and context injection.
func (r *Resolver) ResolveTenant(ctx context.Context, identifier string) (*middleware.TenantConfig, error) {
	// Try UUID parse first; fall back to slug lookup.
	if id, err := uuid.Parse(identifier); err == nil {
		t, err := r.repo.FindByID(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("resolve tenant by id: %w", err)
		}
		return &middleware.TenantConfig{
			TenantID: t.ID.String(),
			Name:     t.Name,
			Active:   t.IsActive(),
		}, nil
	}

	t, err := r.repo.FindBySlug(ctx, identifier)
	if err != nil {
		return nil, fmt.Errorf("resolve tenant by slug: %w", err)
	}
	return &middleware.TenantConfig{
		TenantID: t.ID.String(),
		Name:     t.Name,
		Active:   t.IsActive(),
	}, nil
}

// Ensure Resolver implements middleware.TenantResolver at compile time.
var _ middleware.TenantResolver = (*Resolver)(nil)
