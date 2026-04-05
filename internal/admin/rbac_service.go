package admin

import (
	"context"
	"fmt"

	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/rbac"
)

// RBACService implements api.AdminRBACService using a Casbin PolicyManager.
type RBACService struct {
	enforcer rbac.PolicyManager
	log      *zap.Logger
}

// NewRBACService creates an RBACService backed by the given PolicyManager.
func NewRBACService(enforcer rbac.PolicyManager, log *zap.Logger) *RBACService {
	return &RBACService{enforcer: enforcer, log: log}
}

// ListPolicies returns all policy rules stored in the enforcer.
func (s *RBACService) ListPolicies(ctx context.Context) ([]api.RBACPolicy, error) {
	rules, err := s.enforcer.GetPolicies()
	if err != nil {
		s.log.Error("rbac list policies failed", zap.Error(err))
		return nil, fmt.Errorf("list policies: %w", err)
	}

	out := make([]api.RBACPolicy, 0, len(rules))
	for _, r := range rules {
		if len(r) < 3 {
			continue
		}
		out = append(out, api.RBACPolicy{Subject: r[0], Object: r[1], Action: r[2]})
	}
	return out, nil
}

// AddPolicy creates a new policy rule granting subject permission to perform
// action on object. Idempotent: adding a duplicate rule is not an error.
func (s *RBACService) AddPolicy(ctx context.Context, sub, obj, act string) error {
	if err := s.enforcer.AddPolicy(sub, obj, act); err != nil {
		s.log.Error("rbac add policy failed", zap.String("sub", sub),
			zap.String("obj", obj), zap.String("act", act), zap.Error(err))
		return fmt.Errorf("add policy: %w", err)
	}
	s.log.Info("rbac policy added", zap.String("sub", sub),
		zap.String("obj", obj), zap.String("act", act))
	return nil
}

// RemovePolicy deletes the policy rule for the given (sub, obj, act) triple.
func (s *RBACService) RemovePolicy(ctx context.Context, sub, obj, act string) error {
	if err := s.enforcer.RemovePolicy(sub, obj, act); err != nil {
		s.log.Error("rbac remove policy failed", zap.String("sub", sub),
			zap.String("obj", obj), zap.String("act", act), zap.Error(err))
		return fmt.Errorf("remove policy: %w", err)
	}
	s.log.Info("rbac policy removed", zap.String("sub", sub),
		zap.String("obj", obj), zap.String("act", act))
	return nil
}

// GetRolesForUser returns all roles assigned to the given user (or client) ID.
func (s *RBACService) GetRolesForUser(ctx context.Context, userID string) ([]string, error) {
	roles, err := s.enforcer.GetRolesForUser(userID)
	if err != nil {
		s.log.Error("rbac get roles failed", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("get roles for user: %w", err)
	}
	return roles, nil
}

// AssignRole assigns the given role to the user (or client) ID.
// Idempotent: assigning the same role again is not an error.
func (s *RBACService) AssignRole(ctx context.Context, userID, role string) error {
	if err := s.enforcer.AddRoleForUser(userID, role); err != nil {
		s.log.Error("rbac assign role failed", zap.String("user_id", userID),
			zap.String("role", role), zap.Error(err))
		return fmt.Errorf("assign role: %w", err)
	}
	s.log.Info("rbac role assigned", zap.String("user_id", userID), zap.String("role", role))
	return nil
}

// RemoveRole removes the given role from the user (or client) ID.
func (s *RBACService) RemoveRole(ctx context.Context, userID, role string) error {
	if err := s.enforcer.DeleteRoleForUser(userID, role); err != nil {
		s.log.Error("rbac remove role failed", zap.String("user_id", userID),
			zap.String("role", role), zap.Error(err))
		return fmt.Errorf("remove role: %w", err)
	}
	s.log.Info("rbac role removed", zap.String("user_id", userID), zap.String("role", role))
	return nil
}
