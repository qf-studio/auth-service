package domain

import "time"

// OAuthProvider identifies a supported OAuth identity provider.
type OAuthProvider string

const (
	OAuthProviderGoogle = OAuthProvider("google")
	OAuthProviderGitHub = OAuthProvider("github")
)

// OAuthAccount represents a link between a local user and an external OAuth identity.
// One user may have multiple linked accounts (one per provider).
type OAuthAccount struct {
	ID             string
	UserID         string
	Provider       OAuthProvider
	ProviderUserID string // the ID assigned by the external provider
	Email          string // email returned by the provider (may differ from user email)
	CreatedAt      time.Time
}
