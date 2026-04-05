package rbac

import (
	"context"
	"testing"

	"github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// newTestService creates an RBAC Service with an in-memory adapter for testing.
func newTestService(t *testing.T) *Service {
	t.Helper()
	m, err := model.NewModelFromString(modelText)
	require.NoError(t, err)

	e, err := casbin.NewEnforcer(m)
	require.NoError(t, err)

	return &Service{
		enforcer: e,
		logger:   zap.NewNop(),
	}
}

func TestCheckPermission_NoPolicy(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	allowed, err := svc.CheckPermission(ctx, "alice", "users", "read")
	require.NoError(t, err)
	assert.False(t, allowed, "should deny when no policies exist")
}

func TestAddAndCheckPolicy(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AddPolicy(ctx, "admin", "users", "read")
	require.NoError(t, err)

	tests := []struct {
		name    string
		sub     string
		obj     string
		act     string
		allowed bool
	}{
		{"matching policy", "admin", "users", "read", true},
		{"wrong subject", "user", "users", "read", false},
		{"wrong object", "admin", "tokens", "read", false},
		{"wrong action", "admin", "users", "write", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := svc.CheckPermission(ctx, tt.sub, tt.obj, tt.act)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, ok)
		})
	}
}

func TestRemovePolicy(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AddPolicy(ctx, "admin", "users", "delete")
	require.NoError(t, err)

	ok, err := svc.CheckPermission(ctx, "admin", "users", "delete")
	require.NoError(t, err)
	assert.True(t, ok)

	err = svc.RemovePolicy(ctx, "admin", "users", "delete")
	require.NoError(t, err)

	ok, err = svc.CheckPermission(ctx, "admin", "users", "delete")
	require.NoError(t, err)
	assert.False(t, ok, "should deny after policy removal")
}

func TestRoleHierarchy(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// Grant admin role permission to manage users.
	err := svc.AddPolicy(ctx, "admin", "users", "read")
	require.NoError(t, err)
	err = svc.AddPolicy(ctx, "admin", "users", "write")
	require.NoError(t, err)

	// Assign alice the admin role.
	err = svc.AddRoleForUser(ctx, "alice", "admin")
	require.NoError(t, err)

	// alice should inherit admin permissions.
	ok, err := svc.CheckPermission(ctx, "alice", "users", "read")
	require.NoError(t, err)
	assert.True(t, ok, "alice should inherit admin read")

	ok, err = svc.CheckPermission(ctx, "alice", "users", "write")
	require.NoError(t, err)
	assert.True(t, ok, "alice should inherit admin write")

	// bob has no role — should be denied.
	ok, err = svc.CheckPermission(ctx, "bob", "users", "read")
	require.NoError(t, err)
	assert.False(t, ok, "bob should be denied")
}

func TestMultiLevelRoleHierarchy(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	// superadmin inherits admin.
	err := svc.AddRoleForUser(ctx, "superadmin", "admin")
	require.NoError(t, err)
	// admin has user management.
	err = svc.AddPolicy(ctx, "admin", "users", "delete")
	require.NoError(t, err)

	// Assign user the superadmin role.
	err = svc.AddRoleForUser(ctx, "root-user", "superadmin")
	require.NoError(t, err)

	// root-user → superadmin → admin → users:delete
	ok, err := svc.CheckPermission(ctx, "root-user", "users", "delete")
	require.NoError(t, err)
	assert.True(t, ok, "multi-level hierarchy should resolve")
}

func TestAddRoleForUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AddRoleForUser(ctx, "user1", "admin")
	require.NoError(t, err)

	roles, err := svc.GetRolesForUser(ctx, "user1")
	require.NoError(t, err)
	assert.Equal(t, []string{"admin"}, roles)
}

func TestRemoveRoleForUser(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AddRoleForUser(ctx, "user1", "admin")
	require.NoError(t, err)

	err = svc.RemoveRoleForUser(ctx, "user1", "admin")
	require.NoError(t, err)

	roles, err := svc.GetRolesForUser(ctx, "user1")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestGetRolesForUser_MultipleRoles(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	err := svc.AddRoleForUser(ctx, "user1", "admin")
	require.NoError(t, err)
	err = svc.AddRoleForUser(ctx, "user1", "service")
	require.NoError(t, err)

	roles, err := svc.GetRolesForUser(ctx, "user1")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"admin", "service"}, roles)
}

func TestGetRolesForUser_NoRoles(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	roles, err := svc.GetRolesForUser(ctx, "nobody")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestMultiplePolicies(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()

	policies := []struct{ sub, obj, act string }{
		{"admin", "users", "read"},
		{"admin", "users", "write"},
		{"admin", "users", "delete"},
		{"admin", "clients", "read"},
		{"user", "users", "read"},
		{"service", "tokens", "validate"},
		{"agent", "tokens", "validate"},
	}

	for _, p := range policies {
		err := svc.AddPolicy(ctx, p.sub, p.obj, p.act)
		require.NoError(t, err)
	}

	tests := []struct {
		name    string
		sub     string
		obj     string
		act     string
		allowed bool
	}{
		{"admin reads users", "admin", "users", "read", true},
		{"admin writes users", "admin", "users", "write", true},
		{"admin deletes users", "admin", "users", "delete", true},
		{"admin reads clients", "admin", "clients", "read", true},
		{"admin cannot write clients", "admin", "clients", "write", false},
		{"user reads users", "user", "users", "read", true},
		{"user cannot write users", "user", "users", "write", false},
		{"service validates tokens", "service", "tokens", "validate", true},
		{"agent validates tokens", "agent", "tokens", "validate", true},
		{"agent cannot read users", "agent", "users", "read", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ok, err := svc.CheckPermission(ctx, tt.sub, tt.obj, tt.act)
			require.NoError(t, err)
			assert.Equal(t, tt.allowed, ok)
		})
	}
}
