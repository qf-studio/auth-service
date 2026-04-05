// Package rbac provides role-based access control enforcement.
package rbac

import (
	"context"
	"fmt"

	casbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/jackc/pgx/v5/pgxpool"
	"go.uber.org/zap"
)

// rbacModel is the Casbin model for role-based access control.
// It supports direct policies (p: sub, obj, act) and role inheritance (g).
const rbacModel = `
[request_definition]
r = sub, obj, act

[policy_definition]
p = sub, obj, act

[role_definition]
g = _, _

[policy_effect]
e = some(where (p.eft == allow))

[matchers]
m = g(r.sub, p.sub) && r.obj == p.obj && r.act == p.act
`

// PermissionEnforcer checks whether a subject is permitted to perform
// an action on an object. The subject corresponds to claims.Subject
// (user ID or client ID) as set by AuthMiddleware.
type PermissionEnforcer interface {
	// CheckPermission returns true when the policy allows sub to perform act on obj.
	// It returns an error only for infrastructure failures (database down, etc.).
	CheckPermission(sub, obj, act string) (bool, error)
}

// PolicyManager extends PermissionEnforcer with policy mutation operations
// used by the admin RBAC service.
type PolicyManager interface {
	PermissionEnforcer

	// AddPolicy adds a policy rule: subject may perform action on object.
	AddPolicy(sub, obj, act string) error

	// RemovePolicy removes a policy rule.
	RemovePolicy(sub, obj, act string) error

	// GetPolicies returns all policy rules as [sub, obj, act] triples.
	GetPolicies() ([][]string, error)

	// AddRoleForUser assigns a role to a user (or client).
	AddRoleForUser(user, role string) error

	// DeleteRoleForUser removes a role from a user (or client).
	DeleteRoleForUser(user, role string) error

	// GetRolesForUser returns all roles assigned to the given user.
	GetRolesForUser(user string) ([]string, error)
}

// CasbinEnforcer is a PolicyManager backed by a Casbin enforcer that
// persists policies to PostgreSQL via a custom pgx adapter.
type CasbinEnforcer struct {
	e   *casbin.Enforcer
	log *zap.Logger
}

// NewCasbinEnforcer creates a Casbin enforcer that loads and saves policies
// from the casbin_rule table via the provided PostgreSQL pool.
func NewCasbinEnforcer(pool *pgxpool.Pool, log *zap.Logger) (*CasbinEnforcer, error) {
	m, err := model.NewModelFromString(rbacModel)
	if err != nil {
		return nil, fmt.Errorf("casbin model parse failed: %w", err)
	}

	adapter := newPgxAdapter(pool, log)

	e, err := casbin.NewEnforcer(m, adapter)
	if err != nil {
		return nil, fmt.Errorf("casbin enforcer init failed: %w", err)
	}

	if err := e.LoadPolicy(); err != nil {
		return nil, fmt.Errorf("casbin policy load failed: %w", err)
	}

	return &CasbinEnforcer{e: e, log: log}, nil
}

// CheckPermission reports whether sub may perform act on obj.
func (ce *CasbinEnforcer) CheckPermission(sub, obj, act string) (bool, error) {
	allowed, err := ce.e.Enforce(sub, obj, act)
	if err != nil {
		return false, fmt.Errorf("casbin enforce failed: %w", err)
	}
	return allowed, nil
}

// AddPolicy adds a (sub, obj, act) policy rule and saves to the database.
func (ce *CasbinEnforcer) AddPolicy(sub, obj, act string) error {
	ok, err := ce.e.AddPolicy(sub, obj, act)
	if err != nil {
		return fmt.Errorf("add policy failed: %w", err)
	}
	if !ok {
		// Policy already exists — not an error.
		return nil
	}
	return nil
}

// RemovePolicy removes a (sub, obj, act) policy rule and saves to the database.
func (ce *CasbinEnforcer) RemovePolicy(sub, obj, act string) error {
	_, err := ce.e.RemovePolicy(sub, obj, act)
	if err != nil {
		return fmt.Errorf("remove policy failed: %w", err)
	}
	return nil
}

// GetPolicies returns all policy rules as [sub, obj, act] slices.
func (ce *CasbinEnforcer) GetPolicies() ([][]string, error) {
	return ce.e.GetPolicy()
}

// AddRoleForUser assigns the given role to the user (or client) subject.
func (ce *CasbinEnforcer) AddRoleForUser(user, role string) error {
	_, err := ce.e.AddRoleForUser(user, role)
	if err != nil {
		return fmt.Errorf("add role for user failed: %w", err)
	}
	return nil
}

// DeleteRoleForUser removes the given role from the user (or client) subject.
func (ce *CasbinEnforcer) DeleteRoleForUser(user, role string) error {
	_, err := ce.e.DeleteRoleForUser(user, role)
	if err != nil {
		return fmt.Errorf("delete role for user failed: %w", err)
	}
	return nil
}

// GetRolesForUser returns all roles currently assigned to the given user.
func (ce *CasbinEnforcer) GetRolesForUser(user string) ([]string, error) {
	roles, err := ce.e.GetRolesForUser(user)
	if err != nil {
		return nil, fmt.Errorf("get roles for user failed: %w", err)
	}
	return roles, nil
}

// Reload re-reads all policies from the database.
// Call this after out-of-band policy changes (e.g., direct DB writes).
func (ce *CasbinEnforcer) Reload() error {
	if err := ce.e.LoadPolicy(); err != nil {
		return fmt.Errorf("casbin policy reload failed: %w", err)
	}
	return nil
}

// contextKey is a private type used as the Casbin context key to avoid
// collisions with other packages.
type contextKey struct{}

// FromContext extracts the PermissionEnforcer injected by tests or middleware.
// Returns nil if none has been set.
func FromContext(ctx context.Context) PermissionEnforcer {
	v, _ := ctx.Value(contextKey{}).(PermissionEnforcer)
	return v
}

// NewContext returns a copy of ctx carrying the given enforcer.
// Useful for injecting a test enforcer without changing function signatures.
func NewContext(ctx context.Context, e PermissionEnforcer) context.Context {
	return context.WithValue(ctx, contextKey{}, e)
}
