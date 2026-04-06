package authclient

import (
	"context"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// CheckPermission returns true when subject may perform action on object.
// Returns an error only for transport failures; a "denied" result is returned
// as (false, nil).
func (c *Client) CheckPermission(ctx context.Context, subject, object, action string) (bool, error) {
	var resp *authv1.CheckPermissionResponse

	err := c.do(ctx, func(callCtx context.Context) error {
		var callErr error
		resp, callErr = c.auth.CheckPermission(callCtx, &authv1.CheckPermissionRequest{
			Subject: subject,
			Object:  object,
			Action:  action,
		})
		return callErr
	})
	if err != nil {
		return false, err
	}

	return resp.GetAllowed(), nil
}

// GetUser retrieves a user by ID from the auth service.
func (c *Client) GetUser(ctx context.Context, userID string) (*User, error) {
	var resp *authv1.GetUserResponse

	err := c.do(ctx, func(callCtx context.Context) error {
		var callErr error
		resp, callErr = c.auth.GetUser(callCtx, &authv1.GetUserRequest{
			UserId: userID,
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	return userFromProto(resp.GetUser()), nil
}

// User is the SDK representation of a user returned by the auth service.
type User struct {
	ID            string
	Email         string
	Name          string
	Roles         []string
	Locked        bool
	EmailVerified bool
}

func userFromProto(p *authv1.User) *User {
	if p == nil {
		return nil
	}
	return &User{
		ID:            p.GetId(),
		Email:         p.GetEmail(),
		Name:          p.GetName(),
		Roles:         p.GetRoles(),
		Locked:        p.GetLocked(),
		EmailVerified: p.GetEmailVerified(),
	}
}
