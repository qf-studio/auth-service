package rbac

import (
	"github.com/casbin/casbin/v2/model"
)

// modelText defines a standard RBAC model with role hierarchy.
//
//   - sub: subject (user ID or role name)
//   - obj: resource (e.g. "users", "clients", "tokens")
//   - act: action  (e.g. "read", "write", "delete")
//   - g:   role grouping — maps subjects to roles, supports hierarchy
//
// The matcher resolves the subject's role via g() before checking policy.
const modelText = `
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

// newModel creates a Casbin model from the embedded RBAC definition.
func newModel() (model.Model, error) {
	return model.NewModelFromString(modelText)
}
