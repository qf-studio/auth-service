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

// PasswordPolicyService implements api.AdminPasswordPolicyService.
type PasswordPolicyService struct {
	repo   storage.PasswordPolicyRepository
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewPasswordPolicyService creates a new admin password policy service.
func NewPasswordPolicyService(repo storage.PasswordPolicyRepository, logger *zap.Logger, auditor audit.EventLogger) *PasswordPolicyService {
	return &PasswordPolicyService{
		repo:   repo,
		logger: logger,
		audit:  auditor,
	}
}

// ListPolicies returns a paginated list of password policies.
func (s *PasswordPolicyService) ListPolicies(ctx context.Context, page, perPage int) (*api.AdminPasswordPolicyList, error) {
	offset := (page - 1) * perPage

	policies, total, err := s.repo.List(ctx, perPage, offset)
	if err != nil {
		s.logger.Error("list password policies failed", zap.Error(err))
		return nil, fmt.Errorf("list password policies: %w", api.ErrInternalError)
	}

	result := &api.AdminPasswordPolicyList{
		Policies: make([]api.AdminPasswordPolicy, 0, len(policies)),
		Total:    total,
		Page:     page,
		PerPage:  perPage,
	}

	for _, p := range policies {
		result.Policies = append(result.Policies, domainPolicyToAdmin(p))
	}

	return result, nil
}

// GetPolicy retrieves a single password policy by ID.
func (s *PasswordPolicyService) GetPolicy(ctx context.Context, policyID string) (*api.AdminPasswordPolicy, error) {
	p, err := s.repo.FindByID(ctx, policyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("password policy %s: %w", policyID, api.ErrNotFound)
		}
		s.logger.Error("get password policy failed", zap.String("policy_id", policyID), zap.Error(err))
		return nil, fmt.Errorf("get password policy: %w", api.ErrInternalError)
	}

	admin := domainPolicyToAdmin(p)
	return &admin, nil
}

// CreatePolicy creates a new password policy.
func (s *PasswordPolicyService) CreatePolicy(ctx context.Context, req *api.CreatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
	now := time.Now().UTC()

	policy := &domain.PasswordPolicy{
		ID:           uuid.New().String(),
		Name:         req.Name,
		MinLength:    15,
		MaxLength:    128,
		MaxAgeDays:   0,
		HistoryCount: 0,
		RequireMFA:   false,
		IsDefault:    false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if req.MinLength != nil {
		policy.MinLength = *req.MinLength
	}
	if req.MaxLength != nil {
		policy.MaxLength = *req.MaxLength
	}
	if req.MaxAgeDays != nil {
		policy.MaxAgeDays = *req.MaxAgeDays
	}
	if req.HistoryCount != nil {
		policy.HistoryCount = *req.HistoryCount
	}
	if req.RequireMFA != nil {
		policy.RequireMFA = *req.RequireMFA
	}
	if req.IsDefault != nil {
		policy.IsDefault = *req.IsDefault
	}

	created, err := s.repo.Create(ctx, policy)
	if err != nil {
		if errors.Is(err, storage.ErrDuplicatePolicyName) {
			return nil, fmt.Errorf("policy name already exists: %w", api.ErrConflict)
		}
		s.logger.Error("create password policy failed", zap.Error(err))
		return nil, fmt.Errorf("create password policy: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminPolicyCreate,
		TargetID: created.ID,
		Metadata: map[string]string{"name": created.Name},
	})

	admin := domainPolicyToAdmin(created)
	return &admin, nil
}

// UpdatePolicy modifies password policy fields.
func (s *PasswordPolicyService) UpdatePolicy(ctx context.Context, policyID string, req *api.UpdatePasswordPolicyRequest) (*api.AdminPasswordPolicy, error) {
	existing, err := s.repo.FindByID(ctx, policyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("password policy %s: %w", policyID, api.ErrNotFound)
		}
		s.logger.Error("find password policy for update failed", zap.String("policy_id", policyID), zap.Error(err))
		return nil, fmt.Errorf("update password policy: %w", api.ErrInternalError)
	}

	if req.Name != nil {
		existing.Name = *req.Name
	}
	if req.MinLength != nil {
		existing.MinLength = *req.MinLength
	}
	if req.MaxLength != nil {
		existing.MaxLength = *req.MaxLength
	}
	if req.MaxAgeDays != nil {
		existing.MaxAgeDays = *req.MaxAgeDays
	}
	if req.HistoryCount != nil {
		existing.HistoryCount = *req.HistoryCount
	}
	if req.RequireMFA != nil {
		existing.RequireMFA = *req.RequireMFA
	}
	if req.IsDefault != nil {
		existing.IsDefault = *req.IsDefault
	}

	updated, err := s.repo.Update(ctx, existing)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("password policy %s: %w", policyID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrDuplicatePolicyName) {
			return nil, fmt.Errorf("policy name already exists: %w", api.ErrConflict)
		}
		s.logger.Error("update password policy failed", zap.String("policy_id", policyID), zap.Error(err))
		return nil, fmt.Errorf("update password policy: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminPolicyUpdate,
		TargetID: policyID,
	})

	admin := domainPolicyToAdmin(updated)
	return &admin, nil
}

// DeletePolicy performs a soft delete on a password policy.
func (s *PasswordPolicyService) DeletePolicy(ctx context.Context, policyID string) error {
	err := s.repo.SoftDelete(ctx, policyID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fmt.Errorf("password policy %s: %w", policyID, api.ErrNotFound)
		}
		if errors.Is(err, storage.ErrAlreadyDeleted) {
			return fmt.Errorf("password policy %s already deleted: %w", policyID, api.ErrConflict)
		}
		s.logger.Error("delete password policy failed", zap.String("policy_id", policyID), zap.Error(err))
		return fmt.Errorf("delete password policy: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminPolicyDelete,
		TargetID: policyID,
	})

	return nil
}

// ComplianceReport returns a summary of users violating password policies.
func (s *PasswordPolicyService) ComplianceReport(ctx context.Context) (*api.ComplianceReport, error) {
	data, err := s.repo.ComplianceReport(ctx)
	if err != nil {
		s.logger.Error("compliance report failed", zap.Error(err))
		return nil, fmt.Errorf("compliance report: %w", api.ErrInternalError)
	}

	expiredIDs := data.ExpiredPasswordUserIDs
	if expiredIDs == nil {
		expiredIDs = []string{}
	}
	forceIDs := data.ForceChangeUserIDs
	if forceIDs == nil {
		forceIDs = []string{}
	}

	return &api.ComplianceReport{
		ExpiredPasswordCount:   data.ExpiredPasswordCount,
		ExpiredPasswordUserIDs: expiredIDs,
		ForceChangeCount:       data.ForceChangeCount,
		ForceChangeUserIDs:     forceIDs,
		PolicyViolationCount:   data.PolicyViolationCount,
	}, nil
}

// domainPolicyToAdmin converts a domain.PasswordPolicy to an api.AdminPasswordPolicy DTO.
func domainPolicyToAdmin(p *domain.PasswordPolicy) api.AdminPasswordPolicy {
	return api.AdminPasswordPolicy{
		ID:           p.ID,
		Name:         p.Name,
		MinLength:    p.MinLength,
		MaxLength:    p.MaxLength,
		MaxAgeDays:   p.MaxAgeDays,
		HistoryCount: p.HistoryCount,
		RequireMFA:   p.RequireMFA,
		IsDefault:    p.IsDefault,
		CreatedAt:    p.CreatedAt,
		UpdatedAt:    p.UpdatedAt,
		DeletedAt:    p.DeletedAt,
	}
}
