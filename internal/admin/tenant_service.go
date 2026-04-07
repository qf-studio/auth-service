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

const (
	// minPasswordLength is the absolute minimum a tenant can set for password min_length.
	minPasswordLength = 8
	// maxPasswordLength is the upper bound for password max_length.
	maxPasswordLength = 128
	// minTokenTTL is the minimum allowed token TTL in seconds (30 seconds).
	minTokenTTL = 30
	// maxTokenTTL is the maximum allowed token TTL in seconds (30 days).
	maxTokenTTL = 30 * 24 * 3600

	// validMFAMethods lists the recognised MFA method identifiers.
	mfaMethodTOTP     = "totp"
	mfaMethodWebAuthn = "webauthn"
	mfaMethodBackup   = "backup_codes"
)

var validMFAMethods = map[string]bool{
	mfaMethodTOTP:     true,
	mfaMethodWebAuthn: true,
	mfaMethodBackup:   true,
}

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
func (s *TenantService) ListTenants(ctx context.Context, page, perPage int) (*api.AdminTenantList, error) {
	offset := (page - 1) * perPage

	tenants, total, err := s.repo.List(ctx, perPage, offset)
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

// CreateTenant creates a new tenant with optional configuration.
func (s *TenantService) CreateTenant(ctx context.Context, req *api.CreateTenantRequest) (*api.AdminTenant, error) {
	var cfg domain.TenantConfig
	if req.Config != nil {
		if err := validateTenantConfig(req.Config); err != nil {
			return nil, err
		}
		cfg = adminConfigToDomain(req.Config)
	}

	now := time.Now().UTC()
	tenant := &domain.Tenant{
		ID:        uuid.New(),
		Name:      req.Name,
		Slug:      req.Slug,
		Config:    cfg,
		Status:    domain.TenantStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}

	created, err := s.repo.Create(ctx, tenant)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicateTenant) {
			return nil, fmt.Errorf("tenant slug %s already exists: %w", req.Slug, api.ErrConflict)
		}
		s.logger.Error("create tenant failed", zap.Error(err))
		return nil, fmt.Errorf("create tenant: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminTenantCreate,
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
	if req.Status != nil {
		status := domain.TenantStatus(*req.Status)
		if !status.IsValid() || status == domain.TenantStatusDeleted {
			return nil, fmt.Errorf("invalid status %q: %w", *req.Status, api.ErrConflict)
		}
		existing.Status = status
	}
	if req.Config != nil {
		if err := validateTenantConfig(req.Config); err != nil {
			return nil, err
		}
		existing.Config = adminConfigToDomain(req.Config)
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("tenant %s: %w", tenantID, api.ErrNotFound)
		}
		s.logger.Error("update tenant failed", zap.String("tenant_id", tenantID), zap.Error(err))
		return nil, fmt.Errorf("update tenant: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminTenantUpdate,
		TargetID: tenantID,
	})

	admin := domainTenantToAdmin(updated)
	return &admin, nil
}

// DeleteTenant removes a tenant by ID.
func (s *TenantService) DeleteTenant(ctx context.Context, tenantID string) error {
	id, err := uuid.Parse(tenantID)
	if err != nil {
		return fmt.Errorf("invalid tenant ID: %w", api.ErrNotFound)
	}

	if id == domain.DefaultTenantID {
		return fmt.Errorf("cannot delete default tenant: %w", api.ErrConflict)
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
		Type:     audit.EventAdminTenantDelete,
		TargetID: tenantID,
	})

	return nil
}

// validateTenantConfig validates the tenant configuration fields.
func validateTenantConfig(cfg *api.AdminTenantConfig) error {
	if cfg.PasswordPolicy != nil {
		if err := validatePasswordPolicy(cfg.PasswordPolicy); err != nil {
			return err
		}
	}
	if cfg.MFA != nil {
		if err := validateMFAConfig(cfg.MFA); err != nil {
			return err
		}
	}
	if cfg.AllowedOAuthProviders != nil {
		if err := validateOAuthProviders(cfg.AllowedOAuthProviders); err != nil {
			return err
		}
	}
	if cfg.TokenTTLs != nil {
		if err := validateTokenTTLs(cfg.TokenTTLs); err != nil {
			return err
		}
	}
	return nil
}

func validatePasswordPolicy(pp *api.AdminTenantPasswordPolicy) error {
	if pp.MinLength != nil {
		if *pp.MinLength < minPasswordLength {
			return fmt.Errorf("password min_length must be at least %d: %w", minPasswordLength, api.ErrConflict)
		}
	}
	if pp.MaxLength != nil {
		if *pp.MaxLength > maxPasswordLength {
			return fmt.Errorf("password max_length must not exceed %d: %w", maxPasswordLength, api.ErrConflict)
		}
	}
	if pp.MinLength != nil && pp.MaxLength != nil {
		if *pp.MaxLength < *pp.MinLength {
			return fmt.Errorf("password max_length must be >= min_length: %w", api.ErrConflict)
		}
	}
	if pp.MaxAgeDays != nil && *pp.MaxAgeDays < 0 {
		return fmt.Errorf("password max_age_days must be >= 0: %w", api.ErrConflict)
	}
	if pp.HistoryCount != nil && *pp.HistoryCount < 0 {
		return fmt.Errorf("password history_count must be >= 0: %w", api.ErrConflict)
	}
	return nil
}

func validateMFAConfig(mfa *api.AdminTenantMFAConfig) error {
	for _, method := range mfa.AllowedMethods {
		if !validMFAMethods[method] {
			return fmt.Errorf("invalid MFA method %q: %w", method, api.ErrConflict)
		}
	}
	if mfa.GracePeriodDays < 0 {
		return fmt.Errorf("MFA grace_period_days must be >= 0: %w", api.ErrConflict)
	}
	return nil
}

func validateOAuthProviders(providers []string) error {
	for _, p := range providers {
		if p == "" {
			return fmt.Errorf("OAuth provider name must not be empty: %w", api.ErrConflict)
		}
	}
	return nil
}

func validateTokenTTLs(ttls *api.AdminTenantTokenTTLs) error {
	if ttls.AccessTokenTTL != nil {
		if *ttls.AccessTokenTTL < minTokenTTL || *ttls.AccessTokenTTL > maxTokenTTL {
			return fmt.Errorf("access_token_ttl must be between %d and %d seconds: %w", minTokenTTL, maxTokenTTL, api.ErrConflict)
		}
	}
	if ttls.RefreshTokenTTL != nil {
		if *ttls.RefreshTokenTTL < minTokenTTL || *ttls.RefreshTokenTTL > maxTokenTTL {
			return fmt.Errorf("refresh_token_ttl must be between %d and %d seconds: %w", minTokenTTL, maxTokenTTL, api.ErrConflict)
		}
	}
	return nil
}

// domainTenantToAdmin converts a domain.Tenant to an api.AdminTenant response DTO.
func domainTenantToAdmin(t *domain.Tenant) api.AdminTenant {
	return api.AdminTenant{
		ID:        t.ID.String(),
		Name:      t.Name,
		Slug:      t.Slug,
		Config:    domainConfigToAdmin(t.Config),
		Status:    string(t.Status),
		CreatedAt: t.CreatedAt,
		UpdatedAt: t.UpdatedAt,
	}
}

func domainConfigToAdmin(cfg domain.TenantConfig) api.AdminTenantConfig {
	out := api.AdminTenantConfig{
		AllowedOAuthProviders: cfg.AllowedOAuthProviders,
	}
	if cfg.PasswordPolicy != nil {
		out.PasswordPolicy = &api.AdminTenantPasswordPolicy{
			MinLength:    cfg.PasswordPolicy.MinLength,
			MaxLength:    cfg.PasswordPolicy.MaxLength,
			MaxAgeDays:   cfg.PasswordPolicy.MaxAgeDays,
			HistoryCount: cfg.PasswordPolicy.HistoryCount,
		}
	}
	if cfg.MFA != nil {
		out.MFA = &api.AdminTenantMFAConfig{
			Required:        cfg.MFA.Required,
			AllowedMethods:  cfg.MFA.AllowedMethods,
			GracePeriodDays: cfg.MFA.GracePeriodDays,
		}
	}
	if cfg.TokenTTLs != nil {
		out.TokenTTLs = &api.AdminTenantTokenTTLs{
			AccessTokenTTL:  cfg.TokenTTLs.AccessTokenTTL,
			RefreshTokenTTL: cfg.TokenTTLs.RefreshTokenTTL,
		}
	}
	return out
}

func adminConfigToDomain(cfg *api.AdminTenantConfig) domain.TenantConfig {
	out := domain.TenantConfig{
		AllowedOAuthProviders: cfg.AllowedOAuthProviders,
	}
	if cfg.PasswordPolicy != nil {
		out.PasswordPolicy = &domain.TenantPasswordPolicy{
			MinLength:    cfg.PasswordPolicy.MinLength,
			MaxLength:    cfg.PasswordPolicy.MaxLength,
			MaxAgeDays:   cfg.PasswordPolicy.MaxAgeDays,
			HistoryCount: cfg.PasswordPolicy.HistoryCount,
		}
	}
	if cfg.MFA != nil {
		out.MFA = &domain.TenantMFAConfig{
			Required:        cfg.MFA.Required,
			AllowedMethods:  cfg.MFA.AllowedMethods,
			GracePeriodDays: cfg.MFA.GracePeriodDays,
		}
	}
	if cfg.TokenTTLs != nil {
		out.TokenTTLs = &domain.TenantTokenTTLs{
			AccessTokenTTL:  cfg.TokenTTLs.AccessTokenTTL,
			RefreshTokenTTL: cfg.TokenTTLs.RefreshTokenTTL,
		}
	}
	return out
}
