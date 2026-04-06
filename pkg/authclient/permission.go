package authclient

import (
	"context"
	"fmt"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// CheckPermission evaluates whether subject may perform action on object
// via the auth service RBAC engine. Returns ErrPermissionDenied when the
// action is not allowed.
func (c *Client) CheckPermission(ctx context.Context, subject, object, action string) error {
	ctx, cancel := c.withDeadline(ctx)
	defer cancel()

	var resp *authv1.CheckPermissionResponse
	err := c.retryDo(ctx, func(ctx context.Context) error {
		var rpcErr error
		resp, rpcErr = c.rpc.CheckPermission(ctx, &authv1.CheckPermissionRequest{
			Subject: subject,
			Object:  object,
			Action:  action,
		})
		return rpcErr
	})
	if err != nil {
		return fmt.Errorf("authclient: check permission: %w", err)
	}

	if !resp.GetAllowed() {
		return ErrPermissionDenied
	}
	return nil
}
