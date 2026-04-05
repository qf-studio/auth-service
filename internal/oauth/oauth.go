// Package oauth provides social login via external OAuth providers (Google, GitHub, Apple).
// It handles provider abstraction, PKCE, signed state tokens with CSRF protection,
// and orchestrates account linking / new user creation.
package oauth

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Provider abstracts a single OAuth identity provider.
type Provider interface {
	// Name returns the provider identifier (e.g. "google").
	Name() domain.OAuthProviderType

	// GetAuthURL returns the authorization URL the user should be redirected to.
	// state is the opaque CSRF token; codeChallenge is the S256 PKCE challenge.
	GetAuthURL(state, codeChallenge string) string

	// ExchangeCode exchanges an authorization code for tokens.
	// codeVerifier is the PKCE verifier corresponding to the challenge.
	ExchangeCode(ctx context.Context, code, codeVerifier string) (string, error)

	// GetUser fetches the user profile from the provider using the access token.
	GetUser(ctx context.Context, accessToken string) (*domain.OAuthUser, error)
}
