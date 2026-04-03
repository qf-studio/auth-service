package domain

import "time"

// --- Admin request structs ---

// CreateUserRequest is the validated request body for admin user creation.
type CreateUserRequest struct {
	Email    string   `json:"email"    validate:"required,email"`
	Password string   `json:"password" validate:"required,nist_password"`
	Name     string   `json:"name"     validate:"required,min=1,max=255"`
	Roles    []string `json:"roles"    validate:"omitempty,dive,oneof=admin user"`
}

// UpdateUserRequest is the validated request body for admin user updates.
type UpdateUserRequest struct {
	Email  *string  `json:"email"  validate:"omitempty,email"`
	Name   *string  `json:"name"   validate:"omitempty,min=1,max=255"`
	Roles  []string `json:"roles"  validate:"omitempty,dive,oneof=admin user"`
	Locked *bool    `json:"locked"`
}

// ListUsersRequest holds pagination parameters for listing users.
type ListUsersRequest struct {
	Limit  int    `form:"limit"  validate:"omitempty,min=1,max=100"`
	Offset int    `form:"offset" validate:"omitempty,min=0"`
	Status string `form:"status" validate:"omitempty,oneof=active locked deleted"`
}

// DefaultLimit returns the effective limit, defaulting to 20 if unset.
func (r *ListUsersRequest) DefaultLimit() int {
	if r.Limit == 0 {
		return 20
	}
	return r.Limit
}

// CreateClientRequest is the validated request body for admin client creation.
type CreateClientRequest struct {
	Name       string   `json:"name"        validate:"required,min=1,max=255"`
	ClientType string   `json:"client_type" validate:"required,client_type"`
	Scopes     []string `json:"scopes"      validate:"required,min=1,dive,valid_scope"`
	OwnerID    string   `json:"owner_id"    validate:"omitempty"`
}

// UpdateClientRequest is the validated request body for admin client updates.
type UpdateClientRequest struct {
	Name   *string  `json:"name"   validate:"omitempty,min=1,max=255"`
	Scopes []string `json:"scopes" validate:"omitempty,min=1,dive,valid_scope"`
	Active *bool    `json:"active"`
}

// ListClientsRequest holds pagination parameters for listing clients.
type ListClientsRequest struct {
	Limit      int    `form:"limit"       validate:"omitempty,min=1,max=100"`
	Offset     int    `form:"offset"      validate:"omitempty,min=0"`
	ClientType string `form:"client_type" validate:"omitempty,client_type"`
}

// DefaultLimit returns the effective limit, defaulting to 20 if unset.
func (r *ListClientsRequest) DefaultLimit() int {
	if r.Limit == 0 {
		return 20
	}
	return r.Limit
}

// IntrospectTokenRequest is the validated request body for token introspection (RFC 7662).
type IntrospectTokenRequest struct {
	Token string `json:"token" validate:"required"`
}

// --- Admin response structs ---

// AdminUserResponse is the admin view of a user, including status and timestamps.
type AdminUserResponse struct {
	ID        string     `json:"id"`
	Email     string     `json:"email"`
	Name      string     `json:"name"`
	Roles     []string   `json:"roles"`
	Status    string     `json:"status"`
	Locked    bool       `json:"locked"`
	CreatedAt time.Time  `json:"created_at"`
	UpdatedAt time.Time  `json:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at,omitempty"`
}

// AdminClientResponse is the admin view of an OAuth2 client.
type AdminClientResponse struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ClientID   string    `json:"client_id"`
	ClientType string    `json:"client_type"`
	Scopes     []string  `json:"scopes"`
	OwnerID    string    `json:"owner_id,omitempty"`
	Active     bool      `json:"active"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// IntrospectionResponse follows RFC 7662 token introspection response format.
type IntrospectionResponse struct {
	Active    bool   `json:"active"`
	Sub       string `json:"sub,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Scope     string `json:"scope,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	TokenType string `json:"token_type,omitempty"`
}

// PaginatedResponse is a generic wrapper for paginated list endpoints.
type PaginatedResponse struct {
	Items  interface{} `json:"items"`
	Total  int64       `json:"total"`
	Limit  int         `json:"limit"`
	Offset int         `json:"offset"`
}

// --- Admin validation rules ---

// ValidClientTypes are the allowed client_type values.
var ValidClientTypes = map[string]bool{
	string(ClientTypeService): true,
	string(ClientTypeAgent):   true,
}

// ValidScopes are the allowed OAuth2 scope values for system clients.
var ValidScopes = map[string]bool{
	"read:users":    true,
	"write:users":   true,
	"read:clients":  true,
	"write:clients": true,
	"read:tokens":   true,
	"write:tokens":  true,
	"admin":         true,
}
