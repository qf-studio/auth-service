package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateUserRequest_Validation(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		req     CreateUserRequest
		wantErr bool
	}{
		{
			name: "valid request",
			req: CreateUserRequest{
				Email:    "admin@example.com",
				Password: "a]very$ecurePassw0rd",
				Name:     "Admin User",
				Roles:    []string{"admin"},
			},
			wantErr: false,
		},
		{
			name: "missing email",
			req: CreateUserRequest{
				Password: "a]very$ecurePassw0rd",
				Name:     "Admin User",
			},
			wantErr: true,
		},
		{
			name: "short password",
			req: CreateUserRequest{
				Email:    "admin@example.com",
				Password: "short",
				Name:     "Admin User",
			},
			wantErr: true,
		},
		{
			name: "invalid role",
			req: CreateUserRequest{
				Email:    "admin@example.com",
				Password: "a]very$ecurePassw0rd",
				Name:     "Admin User",
				Roles:    []string{"superadmin"},
			},
			wantErr: true,
		},
		{
			name: "no roles is valid",
			req: CreateUserRequest{
				Email:    "admin@example.com",
				Password: "a]very$ecurePassw0rd",
				Name:     "Admin User",
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUpdateUserRequest_Validation(t *testing.T) {
	v := NewValidator()

	email := "new@example.com"
	badEmail := "notanemail"

	tests := []struct {
		name    string
		req     UpdateUserRequest
		wantErr bool
	}{
		{
			name:    "empty update is valid",
			req:     UpdateUserRequest{},
			wantErr: false,
		},
		{
			name:    "valid email update",
			req:     UpdateUserRequest{Email: &email},
			wantErr: false,
		},
		{
			name:    "invalid email",
			req:     UpdateUserRequest{Email: &badEmail},
			wantErr: true,
		},
		{
			name:    "invalid role in update",
			req:     UpdateUserRequest{Roles: []string{"root"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCreateClientRequest_Validation(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		req     CreateClientRequest
		wantErr bool
	}{
		{
			name: "valid service client",
			req: CreateClientRequest{
				Name:       "My Service",
				ClientType: "service",
				Scopes:     []string{"read:users", "write:users"},
			},
			wantErr: false,
		},
		{
			name: "valid agent client",
			req: CreateClientRequest{
				Name:       "My Agent",
				ClientType: "agent",
				Scopes:     []string{"read:tokens"},
			},
			wantErr: false,
		},
		{
			name: "invalid client_type",
			req: CreateClientRequest{
				Name:       "Bad Type",
				ClientType: "user",
				Scopes:     []string{"read:users"},
			},
			wantErr: true,
		},
		{
			name: "invalid scope",
			req: CreateClientRequest{
				Name:       "Bad Scope",
				ClientType: "service",
				Scopes:     []string{"delete:everything"},
			},
			wantErr: true,
		},
		{
			name: "empty scopes",
			req: CreateClientRequest{
				Name:       "No Scopes",
				ClientType: "service",
			},
			wantErr: true,
		},
		{
			name: "missing name",
			req: CreateClientRequest{
				ClientType: "service",
				Scopes:     []string{"read:users"},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestUpdateClientRequest_Validation(t *testing.T) {
	v := NewValidator()

	name := "Updated Name"

	tests := []struct {
		name    string
		req     UpdateClientRequest
		wantErr bool
	}{
		{
			name:    "empty update is valid",
			req:     UpdateClientRequest{},
			wantErr: false,
		},
		{
			name:    "valid name update",
			req:     UpdateClientRequest{Name: &name},
			wantErr: false,
		},
		{
			name:    "valid scopes update",
			req:     UpdateClientRequest{Scopes: []string{"admin"}},
			wantErr: false,
		},
		{
			name:    "invalid scope in update",
			req:     UpdateClientRequest{Scopes: []string{"nuke:everything"}},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := v.Struct(tt.req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestIntrospectTokenRequest_Validation(t *testing.T) {
	v := NewValidator()

	t.Run("valid", func(t *testing.T) {
		req := IntrospectTokenRequest{Token: "qf_at_abc123"}
		assert.NoError(t, v.Struct(req))
	})

	t.Run("missing token", func(t *testing.T) {
		req := IntrospectTokenRequest{}
		assert.Error(t, v.Struct(req))
	})
}

func TestListUsersRequest_DefaultLimit(t *testing.T) {
	t.Run("returns 20 when unset", func(t *testing.T) {
		r := &ListUsersRequest{}
		assert.Equal(t, 20, r.DefaultLimit())
	})

	t.Run("returns set value", func(t *testing.T) {
		r := &ListUsersRequest{Limit: 50}
		assert.Equal(t, 50, r.DefaultLimit())
	})
}

func TestListClientsRequest_DefaultLimit(t *testing.T) {
	t.Run("returns 20 when unset", func(t *testing.T) {
		r := &ListClientsRequest{}
		assert.Equal(t, 20, r.DefaultLimit())
	})

	t.Run("returns set value", func(t *testing.T) {
		r := &ListClientsRequest{Limit: 10}
		assert.Equal(t, 10, r.DefaultLimit())
	})
}

func TestListUsersRequest_StatusValidation(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name    string
		status  string
		wantErr bool
	}{
		{"empty is valid", "", false},
		{"active", "active", false},
		{"locked", "locked", false},
		{"deleted", "deleted", false},
		{"invalid", "banned", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ListUsersRequest{Status: tt.status}
			err := v.Struct(req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestListClientsRequest_ClientTypeValidation(t *testing.T) {
	v := NewValidator()

	tests := []struct {
		name       string
		clientType string
		wantErr    bool
	}{
		{"empty is valid", "", false},
		{"service", "service", false},
		{"agent", "agent", false},
		{"invalid", "user", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := ListClientsRequest{ClientType: tt.clientType}
			err := v.Struct(req)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidationMessages_AdminTypes(t *testing.T) {
	v := NewValidator()

	t.Run("client_type message", func(t *testing.T) {
		req := CreateClientRequest{
			Name:       "Test",
			ClientType: "invalid",
			Scopes:     []string{"read:users"},
		}
		err := v.Struct(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "client_type")
	})

	t.Run("valid_scope message", func(t *testing.T) {
		req := CreateClientRequest{
			Name:       "Test",
			ClientType: "service",
			Scopes:     []string{"bad:scope"},
		}
		err := v.Struct(req)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "valid_scope")
	})
}
