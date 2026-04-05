// Package rbac provides role-based access control enforcement.
package rbac

import "context"

// Policy represents a Casbin-style (subject, object, action) authorization rule.
type Policy struct {
	Subject string
	Object  string
	Action  string
}

// PolicyRepository defines storage operations for RBAC policies and role assignments.
type PolicyRepository interface {
	// ListPolicies returns all (subject, object, action) policy rules.
	ListPolicies(ctx context.Context) ([]Policy, error)

	// AddPolicy inserts a new policy rule. No-ops on duplicate.
	AddPolicy(ctx context.Context, p Policy) error

	// RemovePolicy deletes a policy rule. Returns ErrNotFound if it does not exist.
	RemovePolicy(ctx context.Context, p Policy) error

	// GetRolesForUser returns all roles assigned to the given user.
	GetRolesForUser(ctx context.Context, user string) ([]string, error)

	// AddRoleForUser assigns a role to a user. No-ops on duplicate.
	AddRoleForUser(ctx context.Context, user, role string) error
}
