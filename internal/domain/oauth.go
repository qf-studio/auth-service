package domain

import "time"

// OAuthAccount represents a linked OAuth provider account for a user.
type OAuthAccount struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// OAuthUser holds the user profile returned by an OAuth provider after token exchange.
type OAuthUser struct {
	ProviderUserID string
	Email          string
	Name           string
}

// OAuthAuthURL is the response for the OAuth initiation endpoint.
type OAuthAuthURL struct {
	AuthURL string `json:"auth_url"`
}

// OAuthLinkedAccounts is the response for listing linked OAuth accounts.
type OAuthLinkedAccounts struct {
	Accounts []OAuthAccount `json:"accounts"`
}
