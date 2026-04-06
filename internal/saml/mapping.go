package saml

import (
	"strings"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Common SAML attribute OID names used by major IdPs.
const (
	// Standard SAML attributes (OASIS).
	AttrEmail     = "urn:oid:0.9.2342.19200300.100.1.3"
	AttrGivenName = "urn:oid:2.5.4.42"
	AttrSurname   = "urn:oid:2.5.4.4"
	AttrFullName  = "urn:oid:2.5.4.3"
	AttrGroups    = "urn:oid:1.3.6.1.4.1.5923.1.1.1.7"

	// Friendly name equivalents (some IdPs use these).
	AttrEmailFriendly     = "email"
	AttrFirstNameFriendly = "firstName"
	AttrLastNameFriendly  = "lastName"
	AttrDisplayName       = "displayName"
	AttrGroupsFriendly    = "groups"
	AttrMemberOf          = "memberOf"
)

// AttributeMapping defines how SAML attributes map to internal user fields for a specific IdP.
type AttributeMapping struct {
	// EmailAttributes is the ordered list of attribute names to check for email.
	EmailAttributes []string

	// NameAttributes is the ordered list of attribute names to check for display name.
	NameAttributes []string

	// GroupAttributes is the ordered list of attribute names to check for group membership.
	GroupAttributes []string

	// GroupRoleMap maps SAML group values to internal role names.
	GroupRoleMap map[string]string

	// DefaultRole is the role assigned when no group mapping matches.
	DefaultRole string
}

// DefaultAttributeMapping returns a mapping that works with most SAML IdPs
// using standard OID and friendly-name attributes.
func DefaultAttributeMapping() AttributeMapping {
	return AttributeMapping{
		EmailAttributes: []string{
			AttrEmail, AttrEmailFriendly,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
		},
		NameAttributes: []string{
			AttrFullName, AttrDisplayName,
			"http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name",
		},
		GroupAttributes: []string{
			AttrGroups, AttrGroupsFriendly, AttrMemberOf,
			"http://schemas.xmlsoap.org/claims/Group",
		},
		GroupRoleMap: map[string]string{},
		DefaultRole: domain.RoleUser,
	}
}

// MappedUser holds the user fields extracted from SAML attributes.
type MappedUser struct {
	Email  string
	Name   string
	Roles  []string
	Groups []string
}

// MapAttributes extracts user fields from SAML assertion attributes using this mapping.
func (m AttributeMapping) MapAttributes(assertion *ParsedAssertion) MappedUser {
	result := MappedUser{}

	// Extract email: check assertion attributes, fall back to NameID if email format.
	result.Email = m.firstValue(assertion.Attributes, m.EmailAttributes)
	if result.Email == "" && assertion.NameIDFormat == NameIDFormatEmailAddress {
		result.Email = assertion.NameID
	}

	// Extract name.
	result.Name = m.firstValue(assertion.Attributes, m.NameAttributes)
	if result.Name == "" {
		// Try to construct from given + surname.
		given := m.firstValue(assertion.Attributes, []string{AttrGivenName, AttrFirstNameFriendly})
		surname := m.firstValue(assertion.Attributes, []string{AttrSurname, AttrLastNameFriendly})
		if given != "" || surname != "" {
			result.Name = strings.TrimSpace(given + " " + surname)
		}
	}

	// Extract groups.
	for _, attr := range m.GroupAttributes {
		if vals, ok := assertion.Attributes[attr]; ok {
			result.Groups = append(result.Groups, vals...)
		}
	}

	// Map groups to roles.
	roleSet := make(map[string]bool)
	for _, group := range result.Groups {
		if role, ok := m.GroupRoleMap[group]; ok && domain.ValidRole(role) {
			roleSet[role] = true
		}
	}

	if len(roleSet) == 0 {
		defaultRole := m.DefaultRole
		if defaultRole == "" {
			defaultRole = domain.RoleUser
		}
		result.Roles = []string{defaultRole}
	} else {
		result.Roles = make([]string, 0, len(roleSet))
		for role := range roleSet {
			result.Roles = append(result.Roles, role)
		}
	}

	return result
}

// firstValue returns the first non-empty value from the attribute map matching the given keys.
func (m AttributeMapping) firstValue(attrs map[string][]string, keys []string) string {
	for _, key := range keys {
		if vals, ok := attrs[key]; ok && len(vals) > 0 && vals[0] != "" {
			return vals[0]
		}
	}
	return ""
}
