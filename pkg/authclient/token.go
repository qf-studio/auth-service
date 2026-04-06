package authclient

import (
	"context"
	"fmt"
	"time"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TokenClaims contains the validated claims from an access token.
type TokenClaims struct {
	Subject       string
	Roles         []string
	Scopes        []string
	ClientType    string
	TokenID       string
	ExpiresAt     time.Time
	IssuedAt      time.Time
	JKTThumbprint string
}

// ValidateToken verifies an access token against the auth service and returns
// its claims. Returns ErrTokenInvalid if the token is expired, revoked, or
// malformed. Returns ErrUnauthenticated if the server rejects the request.
func (c *Client) ValidateToken(ctx context.Context, token string) (*TokenClaims, error) {
	ctx, cancel := c.withDeadline(ctx)
	defer cancel()

	var resp *authv1.ValidateTokenResponse
	err := c.retryDo(ctx, func(ctx context.Context) error {
		var rpcErr error
		resp, rpcErr = c.rpc.ValidateToken(ctx, &authv1.ValidateTokenRequest{
			Token: token,
		})
		return rpcErr
	})
	if err != nil {
		if s, ok := status.FromError(err); ok && s.Code() == codes.Unauthenticated {
			return nil, ErrUnauthenticated
		}
		return nil, fmt.Errorf("authclient: validate token: %w", err)
	}

	if !resp.GetValid() {
		return nil, ErrTokenInvalid
	}

	return claimsFromProto(resp.GetClaims()), nil
}

func claimsFromProto(pb *authv1.TokenClaims) *TokenClaims {
	if pb == nil {
		return &TokenClaims{}
	}
	c := &TokenClaims{
		Subject:       pb.GetSubject(),
		Roles:         pb.GetRoles(),
		Scopes:        pb.GetScopes(),
		ClientType:    pb.GetClientType(),
		TokenID:       pb.GetTokenId(),
		JKTThumbprint: pb.GetJktThumbprint(),
	}
	if pb.GetExpiresAt() != nil {
		c.ExpiresAt = pb.GetExpiresAt().AsTime()
	}
	if pb.GetIssuedAt() != nil {
		c.IssuedAt = pb.GetIssuedAt().AsTime()
	}
	return c
}
