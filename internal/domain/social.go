package domain

import "time"

// OAuthProvider identifies a supported social login provider.
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
	OAuthProviderApple  OAuthProvider = "apple"
)

// ValidOAuthProviders is the set of all recognized provider identifiers.
var ValidOAuthProviders = map[OAuthProvider]bool{
	OAuthProviderGoogle: true,
	OAuthProviderGitHub: true,
	OAuthProviderApple:  true,
}

// SocialAccount links a user to an external OAuth provider account.
type SocialAccount struct {
	ID             string
	UserID         string
	Provider       OAuthProvider
	ProviderUserID string
	Email          string
	Name           string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OAuthUserInfo holds the profile data returned by a social provider
// after a successful token exchange.
type OAuthUserInfo struct {
	ProviderUserID string
	Email          string
	Name           string
	EmailVerified  bool
}
