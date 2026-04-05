package admin

import (
	"context"
	"errors"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/rbac"
)

// RBACService implements api.AdminRBACService using a PolicyRepository.
type RBACService struct {
	repo   rbac.PolicyRepository
	logger *zap.Logger
	audit  audit.EventLogger
}

// NewRBACService creates a new admin RBAC service.
func NewRBACService(repo rbac.PolicyRepository, logger *zap.Logger, auditor audit.EventLogger) *RBACService {
	return &RBACService{
		repo:   repo,
		logger: logger,
		audit:  auditor,
	}
}

// ListPolicies returns all RBAC policy rules.
func (s *RBACService) ListPolicies(ctx context.Context) (*api.AdminPolicyList, error) {
	policies, err := s.repo.ListPolicies(ctx)
	if err != nil {
		s.logger.Error("list policies failed", zap.Error(err))
		return nil, fmt.Errorf("list policies: %w", api.ErrInternalError)
	}

	result := &api.AdminPolicyList{
		Policies: make([]api.AdminPolicy, 0, len(policies)),
		Total:    len(policies),
	}
	for _, p := range policies {
		result.Policies = append(result.Policies, api.AdminPolicy{
			Subject: p.Subject,
			Object:  p.Object,
			Action:  p.Action,
		})
	}
	return result, nil
}

// CreatePolicy adds a new (subject, object, action) rule.
func (s *RBACService) CreatePolicy(ctx context.Context, req *api.CreatePolicyRequest) (*api.AdminPolicy, error) {
	p := rbac.Policy{
		Subject: req.Subject,
		Object:  req.Object,
		Action:  req.Action,
	}

	if err := s.repo.AddPolicy(ctx, p); err != nil {
		s.logger.Error("add policy failed", zap.Error(err))
		return nil, fmt.Errorf("create policy: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminRBACCreate,
		Metadata: map[string]string{"subject": p.Subject, "object": p.Object, "action": p.Action},
	})

	return &api.AdminPolicy{Subject: p.Subject, Object: p.Object, Action: p.Action}, nil
}

// DeletePolicy removes the matching (subject, object, action) rule.
func (s *RBACService) DeletePolicy(ctx context.Context, req *api.DeletePolicyRequest) error {
	p := rbac.Policy{
		Subject: req.Subject,
		Object:  req.Object,
		Action:  req.Action,
	}

	if err := s.repo.RemovePolicy(ctx, p); err != nil {
		if errors.Is(err, rbac.ErrPolicyNotFound) {
			return fmt.Errorf("policy not found: %w", api.ErrNotFound)
		}
		s.logger.Error("remove policy failed", zap.Error(err))
		return fmt.Errorf("delete policy: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminRBACDelete,
		Metadata: map[string]string{"subject": p.Subject, "object": p.Object, "action": p.Action},
	})

	return nil
}

// GetUserRoles returns all roles assigned to the given user.
func (s *RBACService) GetUserRoles(ctx context.Context, user string) (*api.AdminUserRoles, error) {
	roles, err := s.repo.GetRolesForUser(ctx, user)
	if err != nil {
		s.logger.Error("get user roles failed", zap.String("user", user), zap.Error(err))
		return nil, fmt.Errorf("get user roles: %w", api.ErrInternalError)
	}

	return &api.AdminUserRoles{User: user, Roles: roles}, nil
}

// AssignRole assigns role to user and returns the updated role list.
func (s *RBACService) AssignRole(ctx context.Context, req *api.AssignRoleRequest) (*api.AdminUserRoles, error) {
	if err := s.repo.AddRoleForUser(ctx, req.User, req.Role); err != nil {
		s.logger.Error("assign role failed", zap.String("user", req.User), zap.String("role", req.Role), zap.Error(err))
		return nil, fmt.Errorf("assign role: %w", api.ErrInternalError)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventAdminRBACRoleAssign,
		TargetID: req.User,
		Metadata: map[string]string{"role": req.Role},
	})

	roles, err := s.repo.GetRolesForUser(ctx, req.User)
	if err != nil {
		s.logger.Error("get roles after assign failed", zap.String("user", req.User), zap.Error(err))
		return nil, fmt.Errorf("get roles: %w", api.ErrInternalError)
	}

	return &api.AdminUserRoles{User: req.User, Roles: roles}, nil
}
