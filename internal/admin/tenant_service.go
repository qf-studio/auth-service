package admin

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// TenantService implements api.AdminTenantService.
type TenantService struct {
	repo   storage.TenantRepository
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewTenantService creates a new admin tenant service.
func NewTenantService(repo storage.TenantRepository, logger *zap.Logger, auditor audit.EventLogger) *TenantService {
	return &TenantService{
		repo:   repo,
		logger: logger,
		audit:  auditor,
	}
}

// ListTenants returns a paginated list of tenants.
func (s *TenantService) ListTenants(ctx context.Context, page, perPage int, status string) (*api.AdminTenantList, error) {
	offset := (page - 1) * perPage

	tenants, total, err := s.repo.List(ctx, perPage, offset, status)
	if err != nil {
		s.logger.Error("list tenants failed", zap.Error(err))
		return nil, fmt.Errorf("list tenants: %w", api.ErrInternalError)
	}

	result := &api.AdminTenantList{
		Tenants: make([]api.AdminTenant, 0, len(tenants)),
		Total:   total,
		Page:    page,
		PerPage: perPage,
	}

	for _, t := range tenants {
		result.Tenants = append(result.Tenants, domainTenantToAdmin(t))
	}

	return result, nil
}

// GetTenant retrieves a single tenant by ID.
func (s *TenantService) GetTenant(ctx context.Context, tenantID string) (*api.AdminTenant, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", api.ErrNotFound)
	}

	t, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenantID, api.ErrNotFound)
		}
		s.logger.Error("get tenant failed", zap.String("tenant_id", tenantID), zap.Error(err))
		return nil, fmt.Errorf("get tenant: %w", api.ErrInternalError)
	}

	admin := domainTenantToAdmin(t)
	return &admin, nil
}

// CreateTenant creates a new tenant.
func (s *TenantService) CreateTenant(ctx context.Context, req *api.CreateTenantRequest) (*api.AdminTenant, error) {
	now := time.Now().UTC()
	tenant := &domain.Tenant{
		ID:        uuid.New(),
		Name:      req.Name,
		Slug:      req.Slug,
		Config:    req.Config,
		Status:    domain.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	created, err := s.repo.Create(ctx, tenant)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateTenantSlug) {
			return nil, fmt.Errorf("slug already exists: %w", api.ErrConflict)
		}
		s.logger.Error("create tenant failed", zap.Error(err))
		return nil, fmt.Errorf("create tenant: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "admin.tenant.create",
		TargetID: created.ID.String(),
		Metadata: map[string]string{"name": created.Name, "slug": created.Slug},
	})

	admin := domainTenantToAdmin(created)
	return &admin, nil
}

// UpdateTenant modifies tenant fields.
func (s *TenantService) UpdateTenant(ctx context.Context, tenantID string, req *api.UpdateTenantRequest) (*api.AdminTenant, error) {
	id, err := uuid.Parse(tenantID)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant ID: %w", api.ErrNotFound)
	}

	existing, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenantID, api.ErrNotFound)
		}
		s.logger.Error("find tenant for update failed", zap.String("tenant_id", tenantID), zap.Error(err))
		return nil, fmt.Errorf("update tenant: %w", api.ErrInternalError)
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.Slug != nil {
		existing.Slug = *req.Slug
	}
	if req.Config != nil {
		existing.Config = *req.Config
	}
	if req.Status != nil {
		existing.Status = domain.TenantStatus(*req.Status)
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenantID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrDuplicateTenantSlug) {
			return nil, fmt.Errorf("slug already exists: %w", api.ErrConflict)
		}
		s.logger.Error("update tenant failed", zap.String("tenant_id", tenantID), zap.Error(err))
		return nil, fmt.Errorf("update tenant: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "admin.tenant.update",
		TargetID: tenantID,
	})

	admin := domainTenantToAdmin(updated)
	return &admin, nil
}

// DeleteTenant performs a soft delete.
func (s *TenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	id, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", api.ErrNotFound)
	}

	err = s.repo.Delete(ctx, id)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("tenant %s: %w", tenantID, api.ErrNotFound)
		}
		s.logger.Error("delete tenant failed", zap.String("tenant_id", tenantID), zap.Error(err))
		return fmt.Errorf("delete tenant: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     "admin.tenant.delete",
		TargetID: tenantID,
	})
	return nil
}

func domainTenantToAdmin(t *domain.Tenant) api.AdminTenant {
	return api.AdminTenant{
		ID:        t.ID.String(),
		Name:      t.Name,
		Slug:      t.Slug,
		Config:    t.Config,
		Status:    string(t.Status),
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

// Ensure TenantService implements the interface at compile time.
var _ api.AdminTenantService = (*TenantService)(nil)
