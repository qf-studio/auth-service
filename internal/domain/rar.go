package domain

// AuthorizationDetail represents a single entry in the authorization_details
// parameter defined by RFC 9396 (Rich Authorization Requests).
type AuthorizationDetail struct {
	// Type is the mandatory authorization type identifier (RFC 9396 §2).
	Type string `json:"type"`

	// Locations are the resource server locations where the authorization applies.
	Locations []string `json:"locations,omitempty"`

	// Actions are the operations the client wants to perform.
	Actions []string `json:"actions,omitempty"`

	// DataTypes are the types of data the client wants to access.
	DataTypes []string `json:"datatypes,omitempty"`

	// Identifier is a specific resource identifier.
	Identifier string `json:"identifier,omitempty"`

	// Privileges are the privileges the client requests.
	Privileges []string `json:"privileges,omitempty"`
}
