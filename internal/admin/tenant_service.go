package admin

import (
	"context"
	"fmt"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Tenant audit event type constants.
const (
	eventAdminTenantCreate = "admin_tenant_create"
	eventAdminTenantUpdate = "admin_tenant_update"
	eventAdminTenantDelete = "admin_tenant_delete"
)

// TenantService implements admin tenant management operations.
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

// GetTenant returns a tenant by ID.
func (s *TenantService) GetTenant(ctx context.Context, id string) (*domain.Tenant, error) {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return nil, fmt.Errorf("invalid tenant id: %w", err)
	}
	tenant, err := s.repo.FindByID(ctx, parsed)
	if err != nil {
		return nil, fmt.Errorf("get tenant: %w", err)
	}
	return tenant, nil
}

// ListTenants returns a paginated list of tenants.
func (s *TenantService) ListTenants(ctx context.Context, page, perPage int) ([]*domain.Tenant, int, error) {
	offset := (page - 1) * perPage
	tenants, total, err := s.repo.List(ctx, perPage, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list tenants: %w", err)
	}
	return tenants, total, nil
}

// CreateTenant creates a new tenant.
func (s *TenantService) CreateTenant(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	created, err := s.repo.Create(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("create tenant: %w", err)
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     eventAdminTenantCreate,
		TargetID: created.ID.String(),
	})
	return created, nil
}

// UpdateTenant updates an existing tenant.
func (s *TenantService) UpdateTenant(ctx context.Context, tenant *domain.Tenant) (*domain.Tenant, error) {
	updated, err := s.repo.Update(ctx, tenant)
	if err != nil {
		return nil, fmt.Errorf("update tenant: %w", err)
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     eventAdminTenantUpdate,
		TargetID: updated.ID.String(),
	})
	return updated, nil
}

// DeleteTenant removes a tenant by ID.
func (s *TenantService) DeleteTenant(ctx context.Context, id string) error {
	parsed, err := uuid.Parse(id)
	if err != nil {
		return fmt.Errorf("invalid tenant id: %w", err)
	}
	if err := s.repo.Delete(ctx, parsed); err != nil {
		return fmt.Errorf("delete tenant: %w", err)
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     eventAdminTenantDelete,
		TargetID: id,
	})
	return nil
}
