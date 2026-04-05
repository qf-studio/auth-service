package domain

import "time"

// OAuthProviderType identifies a supported OAuth provider.
type OAuthProviderType string

const (
	OAuthProviderGoogle OAuthProviderType = "google"
	OAuthProviderGitHub OAuthProviderType = "github"
	OAuthProviderApple  OAuthProviderType = "apple"
)

// ValidOAuthProviders returns the set of recognised provider identifiers.
func ValidOAuthProviders() []OAuthProviderType {
	return []OAuthProviderType{
		OAuthProviderGoogle,
		OAuthProviderGitHub,
		OAuthProviderApple,
	}
}

// IsValidOAuthProvider checks whether the given string is a recognised provider.
func IsValidOAuthProvider(p string) bool {
	for _, v := range ValidOAuthProviders() {
		if string(v) == p {
			return true
		}
	}
	return false
}

// OAuthAccount represents a linked social login account stored in the database.
type OAuthAccount struct {
	ID             string
	UserID         string
	Provider       OAuthProviderType
	ProviderUserID string
	Email          string
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OAuthUser is the intermediate user profile returned by an OAuth provider
// after a successful code exchange. It is not persisted directly.
type OAuthUser struct {
	ProviderUserID string
	Email          string
	Name           string
	AvatarURL      string
}
