package rbac

import (
	"context"
	"fmt"
	"sync"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/persist"
	"go.uber.org/zap"
)

// Enforcer defines the RBAC permission checking interface.
type Enforcer interface {
	// CheckPermission returns true if the subject is allowed to perform
	// the action on the object. Returns an error only on system failures.
	CheckPermission(ctx context.Context, sub, obj, act string) (bool, error)

	// AddPolicy grants a subject permission to perform an action on an object.
	AddPolicy(ctx context.Context, sub, obj, act string) error

	// RemovePolicy revokes a specific permission.
	RemovePolicy(ctx context.Context, sub, obj, act string) error

	// AddRoleForUser assigns a role to a user (role grouping).
	AddRoleForUser(ctx context.Context, user, role string) error

	// RemoveRoleForUser removes a role from a user.
	RemoveRoleForUser(ctx context.Context, user, role string) error

	// GetRolesForUser returns all roles assigned to a user.
	GetRolesForUser(ctx context.Context, user string) ([]string, error)

	// LoadPolicy reloads policies from the adapter.
	LoadPolicy(ctx context.Context) error

	// LoadFilteredPolicy reloads only policies matching the filter.
	LoadFilteredPolicy(ctx context.Context, filter *PolicyFilter) error
}

// Service wraps a Casbin enforcer with logging and concurrency safety.
type Service struct {
	enforcer *casbin.Enforcer
	logger   *zap.Logger
	mu       sync.RWMutex
}

// NewService creates a new RBAC enforcement service.
// The adapter must implement persist.FilteredAdapter for filtered policy loading.
func NewService(adapter persist.FilteredAdapter, logger *zap.Logger) (*Service, error) {
	m, err := newModel()
	if err != nil {
		return nil, fmt.Errorf("rbac: build model: %w", err)
	}

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("rbac: create enforcer: %w", err)
	}

	return &Service{
		enforcer: e,
		logger:   logger,
	}, nil
}

// CheckPermission evaluates whether sub may perform act on obj.
func (s *Service) CheckPermission(_ context.Context, sub, obj, act string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	allowed, err := s.enforcer.Enforce(sub, obj, act)
	if err != nil {
		s.logger.Error("rbac enforcement failed",
			zap.String("sub", sub),
			zap.String("obj", obj),
			zap.String("act", act),
			zap.Error(err),
		)
		return false, fmt.Errorf("rbac: enforce: %w", err)
	}

	s.logger.Debug("rbac check",
		zap.String("sub", sub),
		zap.String("obj", obj),
		zap.String("act", act),
		zap.Bool("allowed", allowed),
	)
	return allowed, nil
}

// AddPolicy grants a permission and persists it via the adapter.
func (s *Service) AddPolicy(_ context.Context, sub, obj, act string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.enforcer.AddPolicy(sub, obj, act); err != nil {
		return fmt.Errorf("rbac: add policy: %w", err)
	}
	s.logger.Info("rbac policy added",
		zap.String("sub", sub),
		zap.String("obj", obj),
		zap.String("act", act),
	)
	return nil
}

// RemovePolicy revokes a permission and removes it from the adapter.
func (s *Service) RemovePolicy(_ context.Context, sub, obj, act string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.enforcer.RemovePolicy(sub, obj, act); err != nil {
		return fmt.Errorf("rbac: remove policy: %w", err)
	}
	s.logger.Info("rbac policy removed",
		zap.String("sub", sub),
		zap.String("obj", obj),
		zap.String("act", act),
	)
	return nil
}

// AddRoleForUser assigns a role to a user in the role grouping (g).
func (s *Service) AddRoleForUser(_ context.Context, user, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.enforcer.AddGroupingPolicy(user, role); err != nil {
		return fmt.Errorf("rbac: add role for user: %w", err)
	}
	s.logger.Info("rbac role assigned",
		zap.String("user", user),
		zap.String("role", role),
	)
	return nil
}

// RemoveRoleForUser removes a role assignment from a user.
func (s *Service) RemoveRoleForUser(_ context.Context, user, role string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.enforcer.RemoveGroupingPolicy(user, role); err != nil {
		return fmt.Errorf("rbac: remove role for user: %w", err)
	}
	s.logger.Info("rbac role removed",
		zap.String("user", user),
		zap.String("role", role),
	)
	return nil
}

// GetRolesForUser returns all roles assigned to a user.
func (s *Service) GetRolesForUser(_ context.Context, user string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	roles, err := s.enforcer.GetRolesForUser(user)
	if err != nil {
		return nil, fmt.Errorf("rbac: get roles for user: %w", err)
	}
	return roles, nil
}

// LoadPolicy reloads all policies from the adapter.
func (s *Service) LoadPolicy(_ context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enforcer.LoadPolicy(); err != nil {
		return fmt.Errorf("rbac: load policy: %w", err)
	}
	s.logger.Info("rbac policies reloaded")
	return nil
}

// LoadFilteredPolicy reloads only policies matching the filter.
func (s *Service) LoadFilteredPolicy(_ context.Context, filter *PolicyFilter) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.enforcer.LoadFilteredPolicy(filter); err != nil {
		return fmt.Errorf("rbac: load filtered policy: %w", err)
	}
	s.logger.Info("rbac filtered policies reloaded")
	return nil
}
