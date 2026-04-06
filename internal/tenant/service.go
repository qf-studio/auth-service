// Package tenant provides tenant management and resolution for the multi-tenant auth service.
package tenant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/middleware"
	"github.com/qf-studio/auth-service/internal/storage"
)

// slugPattern enforces DNS-safe tenant slugs: lowercase alphanumeric with hyphens,
// must start and end with alphanumeric.
var slugPattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

// Service wraps the tenant repository with business logic, validation,
// and implements middleware.TenantResolver.
type Service struct {
	repo   storage.TenantRepository
	logger *zap.Logger
	cfg    config.TenantConfig
}

// NewService creates a new tenant Service.
func NewService(repo storage.TenantRepository, logger *zap.Logger, cfg config.TenantConfig) *Service {
	return &Service{repo: repo, logger: logger, cfg: cfg}
}

// Create validates and persists a new tenant.
func (s *Service) Create(ctx context.Context, slug, name string) (*domain.Tenant, error) {
	slug = strings.ToLower(strings.TrimSpace(slug))
	name = strings.TrimSpace(name)

	if err := s.validateSlug(slug); err != nil {
		return nil, err
	}
	if err := s.validateName(name); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	tenant := &domain.Tenant{
		ID:        "tnt_" + generateID(),
		Slug:      slug,
		Name:      name,
		Active:    true,
		CreatedAt: now,
		UpdatedAt: now,
	}

	created, err := s.repo.Create(ctx, tenant)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateTenantSlug) {
			return nil, fmt.Errorf("slug %q: %w", slug, storage.ErrDuplicateTenantSlug)
		}
		return nil, fmt.Errorf("create tenant: %w", err)
	}

	s.logger.Info("tenant created", zap.String("tenant_id", created.ID), zap.String("slug", created.Slug))
	return created, nil
}

// FindByID returns a tenant by its ID.
func (s *Service) FindByID(ctx context.Context, id string) (*domain.Tenant, error) {
	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", id, domain.ErrTenantNotFound)
		}
		return nil, fmt.Errorf("find tenant: %w", err)
	}
	return t, nil
}

// FindBySlug returns a tenant by its slug.
func (s *Service) FindBySlug(ctx context.Context, slug string) (*domain.Tenant, error) {
	t, err := s.repo.FindBySlug(ctx, slug)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", slug, domain.ErrTenantNotFound)
		}
		return nil, fmt.Errorf("find tenant: %w", err)
	}
	return t, nil
}

// List returns a paginated list of tenants.
func (s *Service) List(ctx context.Context, limit, offset int, includeDeleted bool) ([]*domain.Tenant, int, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}
	if offset < 0 {
		offset = 0
	}
	return s.repo.List(ctx, limit, offset, includeDeleted)
}

// Update modifies a tenant's mutable fields.
func (s *Service) Update(ctx context.Context, id, slug, name string, active *bool) (*domain.Tenant, error) {
	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", id, domain.ErrTenantNotFound)
		}
		return nil, fmt.Errorf("find tenant: %w", err)
	}

	if slug != "" {
		slug = strings.ToLower(strings.TrimSpace(slug))
		if err := s.validateSlug(slug); err != nil {
			return nil, err
		}
		existing.Slug = slug
	}
	if name != "" {
		name = strings.TrimSpace(name)
		if err := s.validateName(name); err != nil {
			return nil, err
		}
		existing.Name = name
	}
	if active != nil {
		existing.Active = *active
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateTenantSlug) {
			return nil, fmt.Errorf("slug %q: %w", existing.Slug, storage.ErrDuplicateTenantSlug)
		}
		return nil, fmt.Errorf("update tenant: %w", err)
	}

	s.logger.Info("tenant updated", zap.String("tenant_id", updated.ID), zap.String("slug", updated.Slug))
	return updated, nil
}

// Delete soft-deletes a tenant.
func (s *Service) Delete(ctx context.Context, id string) error {
	if err := s.repo.Delete(ctx, id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("tenant %s: %w", id, domain.ErrTenantNotFound)
		}
		if errors.Is(err, storage.ErrAlreadyDeleted) {
			return fmt.Errorf("tenant %s: %w", id, storage.ErrAlreadyDeleted)
		}
		return fmt.Errorf("delete tenant: %w", err)
	}

	s.logger.Info("tenant deleted", zap.String("tenant_id", id))
	return nil
}

// ResolveTenant implements middleware.TenantResolver. It looks up a tenant
// by ID or slug and returns the middleware-level TenantConfig.
func (s *Service) ResolveTenant(ctx context.Context, identifier string) (*middleware.TenantConfig, error) {
	// Try by ID first (IDs have the "tnt_" prefix), then by slug.
	var t *domain.Tenant
	var err error

	if strings.HasPrefix(identifier, "tnt_") {
		t, err = s.repo.FindByID(ctx, identifier)
	} else {
		t, err = s.repo.FindBySlug(ctx, identifier)
	}

	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", identifier, domain.ErrTenantNotFound)
		}
		return nil, fmt.Errorf("resolve tenant: %w", err)
	}

	return &middleware.TenantConfig{
		TenantID: t.ID,
		Name:     t.Name,
		Active:   t.IsActive(),
	}, nil
}

func (s *Service) validateSlug(slug string) error {
	if len(slug) < s.cfg.SlugMinLength {
		return fmt.Errorf("slug must be at least %d characters", s.cfg.SlugMinLength)
	}
	if len(slug) > s.cfg.SlugMaxLength {
		return fmt.Errorf("slug must be at most %d characters", s.cfg.SlugMaxLength)
	}
	if !slugPattern.MatchString(slug) {
		return fmt.Errorf("slug must be lowercase alphanumeric with hyphens, starting and ending with alphanumeric")
	}
	return nil
}

func (s *Service) validateName(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if len(name) > s.cfg.NameMaxLength {
		return fmt.Errorf("name must be at most %d characters", s.cfg.NameMaxLength)
	}
	return nil
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Compile-time assertion that Service implements middleware.TenantResolver.
var _ middleware.TenantResolver = (*Service)(nil)
