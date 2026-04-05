package rbac_test

import (
	"testing"

	casbin "github.com/casbin/casbin/v2"
	"github.com/casbin/casbin/v2/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/rbac"
)

const testRBACModel = `
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

// newTestEnforcer creates a PolicyManager backed by an in-memory Casbin
// enforcer (no database required). Used for unit tests only.
func newTestEnforcer(t *testing.T) rbac.PolicyManager {
	t.Helper()

	m, err := model.NewModelFromString(testRBACModel)
	require.NoError(t, err)

	// No adapter — starts with no policies (nil adapter skips LoadPolicy).
	e, err := casbin.NewEnforcer(m)
	require.NoError(t, err)

	return &testEnforcer{e: e}
}

// testEnforcer wraps *casbin.Enforcer and satisfies PolicyManager without
// needing a database. Only used in this test file.
type testEnforcer struct {
	e *casbin.Enforcer
}

func (te *testEnforcer) CheckPermission(sub, obj, act string) (bool, error) {
	return te.e.Enforce(sub, obj, act)
}

func (te *testEnforcer) AddPolicy(sub, obj, act string) error {
	_, err := te.e.AddPolicy(sub, obj, act)
	return err
}

func (te *testEnforcer) RemovePolicy(sub, obj, act string) error {
	_, err := te.e.RemovePolicy(sub, obj, act)
	return err
}

func (te *testEnforcer) GetPolicies() ([][]string, error) {
	return te.e.GetPolicy()
}

func (te *testEnforcer) AddRoleForUser(user, role string) error {
	_, err := te.e.AddRoleForUser(user, role)
	return err
}

func (te *testEnforcer) DeleteRoleForUser(user, role string) error {
	_, err := te.e.DeleteRoleForUser(user, role)
	return err
}

func (te *testEnforcer) GetRolesForUser(user string) ([]string, error) {
	return te.e.GetRolesForUser(user)
}

// compile-time assertion
var _ rbac.PolicyManager = (*testEnforcer)(nil)

// --- Tests ---

func TestCheckPermission_DirectPolicy(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddPolicy("alice", "/tokens", "read"))

	allowed, err := e.CheckPermission("alice", "/tokens", "read")
	require.NoError(t, err)
	assert.True(t, allowed)

	denied, err := e.CheckPermission("alice", "/tokens", "write")
	require.NoError(t, err)
	assert.False(t, denied)
}

func TestCheckPermission_RoleInheritance(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddPolicy("admin", "/tokens", "write"))
	require.NoError(t, e.AddRoleForUser("bob", "admin"))

	allowed, err := e.CheckPermission("bob", "/tokens", "write")
	require.NoError(t, err)
	assert.True(t, allowed, "bob should inherit write access from admin role")
}

func TestCheckPermission_UnknownSubjectDenied(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddPolicy("alice", "/tokens", "read"))

	denied, err := e.CheckPermission("carol", "/tokens", "read")
	require.NoError(t, err)
	assert.False(t, denied)
}

func TestAddRemovePolicy(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddPolicy("alice", "/clients", "delete"))

	policies, err := e.GetPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1)

	require.NoError(t, e.RemovePolicy("alice", "/clients", "delete"))

	policies, err = e.GetPolicies()
	require.NoError(t, err)
	assert.Empty(t, policies)
}

func TestGetRolesForUser(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddRoleForUser("dave", "operator"))
	require.NoError(t, e.AddRoleForUser("dave", "auditor"))

	roles, err := e.GetRolesForUser("dave")
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"operator", "auditor"}, roles)
}

func TestDeleteRoleForUser(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddRoleForUser("eve", "admin"))
	require.NoError(t, e.DeleteRoleForUser("eve", "admin"))

	roles, err := e.GetRolesForUser("eve")
	require.NoError(t, err)
	assert.Empty(t, roles)
}

func TestAddDuplicatePolicyIsIdempotent(t *testing.T) {
	e := newTestEnforcer(t)

	require.NoError(t, e.AddPolicy("frank", "/users", "list"))
	require.NoError(t, e.AddPolicy("frank", "/users", "list")) // duplicate should not error

	policies, err := e.GetPolicies()
	require.NoError(t, err)
	assert.Len(t, policies, 1, "duplicate policy should not be stored twice")
}

// TestPermissionEnforcerInterface verifies compile-time satisfiability.
func TestPermissionEnforcerInterface(t *testing.T) {
	var _ rbac.PermissionEnforcer = newTestEnforcer(t)
}
