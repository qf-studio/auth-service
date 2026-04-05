package rbac

import (
	"context"
	"errors"
	"sync"
)

// ErrPolicyNotFound is returned when a policy to be removed does not exist.
var ErrPolicyNotFound = errors.New("policy not found")

// MemoryRepository is a thread-safe in-memory implementation of PolicyRepository.
// It is intended for development and testing; replace with a PostgreSQL-backed
// implementation (e.g., via Casbin's pgx adapter) for production.
type MemoryRepository struct {
	mu      sync.RWMutex
	policies []Policy
	roles    map[string][]string // user → []role
}

// NewMemoryRepository creates an empty MemoryRepository.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		roles: make(map[string][]string),
	}
}

// ListPolicies returns a copy of all stored policy rules.
func (r *MemoryRepository) ListPolicies(_ context.Context) ([]Policy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Policy, len(r.policies))
	copy(result, r.policies)
	return result, nil
}

// AddPolicy inserts a policy rule if it does not already exist.
func (r *MemoryRepository) AddPolicy(_ context.Context, p Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.policies {
		if existing == p {
			return nil // idempotent
		}
	}
	r.policies = append(r.policies, p)
	return nil
}

// RemovePolicy deletes the matching policy rule.
// Returns ErrPolicyNotFound if no matching rule exists.
func (r *MemoryRepository) RemovePolicy(_ context.Context, p Policy) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for i, existing := range r.policies {
		if existing == p {
			r.policies = append(r.policies[:i], r.policies[i+1:]...)
			return nil
		}
	}
	return ErrPolicyNotFound
}

// GetRolesForUser returns a copy of roles assigned to user.
func (r *MemoryRepository) GetRolesForUser(_ context.Context, user string) ([]string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	roles := r.roles[user]
	result := make([]string, len(roles))
	copy(result, roles)
	return result, nil
}

// AddRoleForUser assigns role to user if not already present.
func (r *MemoryRepository) AddRoleForUser(_ context.Context, user, role string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, existing := range r.roles[user] {
		if existing == role {
			return nil // idempotent
		}
	}
	r.roles[user] = append(r.roles[user], role)
	return nil
}
