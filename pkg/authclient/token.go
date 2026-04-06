package authclient

import (
	"context"
	"time"

	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// TokenClaims holds validated token claims returned by the auth service.
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

// ValidationResult is the response from a ValidateToken call.
type ValidationResult struct {
	Valid  bool
	Claims *TokenClaims
}

// ValidateToken verifies the given access token against the auth service.
// Returns ValidationResult with Valid=false (and no error) when the token
// is syntactically recognisable but invalid/expired. Returns an error only
// for transport failures.
func (c *Client) ValidateToken(ctx context.Context, accessToken string) (*ValidationResult, error) {
	var resp *authv1.ValidateTokenResponse

	err := c.do(ctx, func(callCtx context.Context) error {
		var callErr error
		resp, callErr = c.auth.ValidateToken(callCtx, &authv1.ValidateTokenRequest{
			AccessToken: accessToken,
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	result := &ValidationResult{Valid: resp.GetValid()}
	if resp.GetClaims() != nil {
		result.Claims = claimsFromProto(resp.GetClaims())
	}
	return result, nil
}

// IntrospectToken returns detailed RFC 7662-style metadata for the token.
// Active=false (with no error) when the token is inactive.
type IntrospectResult struct {
	Active bool
	Claims *TokenClaims
}

// IntrospectToken calls the IntrospectToken RPC and returns structured metadata.
func (c *Client) IntrospectToken(ctx context.Context, accessToken string) (*IntrospectResult, error) {
	var resp *authv1.IntrospectTokenResponse

	err := c.do(ctx, func(callCtx context.Context) error {
		var callErr error
		resp, callErr = c.auth.IntrospectToken(callCtx, &authv1.IntrospectTokenRequest{
			AccessToken: accessToken,
		})
		return callErr
	})
	if err != nil {
		return nil, err
	}

	result := &IntrospectResult{Active: resp.GetActive()}
	if resp.GetClaims() != nil {
		result.Claims = claimsFromProto(resp.GetClaims())
	}
	return result, nil
}

func claimsFromProto(p *authv1.TokenClaims) *TokenClaims {
	return &TokenClaims{
		Subject:       p.GetSubject(),
		Roles:         p.GetRoles(),
		Scopes:        p.GetScopes(),
		ClientType:    p.GetClientType(),
		TokenID:       p.GetTokenId(),
		ExpiresAt:     time.Unix(p.GetExpiresAt(), 0),
		IssuedAt:      time.Unix(p.GetIssuedAt(), 0),
		JKTThumbprint: p.GetJktThumbprint(),
	}
}
