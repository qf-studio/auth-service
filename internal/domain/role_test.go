package domain_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestValidRole(t *testing.T) {
	tests := []struct {
		role  string
		valid bool
	}{
		{domain.RoleAdmin, true},
		{domain.RoleUser, true},
		{domain.RoleService, true},
		{domain.RoleAgent, true},
		{"superuser", false},
		{"", false},
		{"ADMIN", false},
	}

	for _, tt := range tests {
		t.Run(tt.role, func(t *testing.T) {
			assert.Equal(t, tt.valid, domain.ValidRole(tt.role))
		})
	}
}

func TestValidRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles []string
		valid bool
	}{
		{"single valid role", []string{domain.RoleAdmin}, true},
		{"multiple valid roles", []string{domain.RoleUser, domain.RoleAdmin}, true},
		{"all roles", []string{domain.RoleAdmin, domain.RoleUser, domain.RoleService, domain.RoleAgent}, true},
		{"empty slice", []string{}, false},
		{"nil slice", nil, false},
		{"one invalid role", []string{domain.RoleUser, "superuser"}, false},
		{"all invalid", []string{"superuser", "root"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.valid, domain.ValidRoles(tt.roles))
		})
	}
}

func TestRoleConstants_Unique(t *testing.T) {
	roles := []string{domain.RoleAdmin, domain.RoleUser, domain.RoleService, domain.RoleAgent}
	seen := make(map[string]bool)
	for _, r := range roles {
		assert.False(t, seen[r], "duplicate role constant: %s", r)
		seen[r] = true
	}
}

func TestClientStatusConstants_Unique(t *testing.T) {
	statuses := []string{domain.ClientStatusActive, domain.ClientStatusSuspended, domain.ClientStatusRevoked}
	seen := make(map[string]bool)
	for _, s := range statuses {
		assert.False(t, seen[s], "duplicate client status constant: %s", s)
		seen[s] = true
	}
}
