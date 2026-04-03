package domain

// Role string constants. Stored as strings for readability in DB and logs.
const (
	RoleAdmin   = "admin"
	RoleUser    = "user"
	RoleService = "service"
	RoleAgent   = "agent"
)

// validRoles is the authoritative set of all recognised role values.
var validRoles = map[string]bool{
	RoleAdmin:   true,
	RoleUser:    true,
	RoleService: true,
	RoleAgent:   true,
}

// ValidRole returns true if r is a recognised role.
func ValidRole(r string) bool {
	return validRoles[r]
}

// ValidRoles returns true if every element of roles is a recognised role
// and the slice is non-empty.
func ValidRoles(roles []string) bool {
	if len(roles) == 0 {
		return false
	}
	for _, r := range roles {
		if !validRoles[r] {
			return false
		}
	}
	return true
}
