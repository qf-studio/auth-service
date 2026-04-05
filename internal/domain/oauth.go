package domain

import "time"

// OAuthProvider represents a supported external OAuth identity provider.
type OAuthProvider string

const (
	OAuthProviderGoogle OAuthProvider = "google"
	OAuthProviderGitHub OAuthProvider = "github"
)

// ValidOAuthProviders is the set of currently supported providers.
var ValidOAuthProviders = map[OAuthProvider]bool{
	OAuthProviderGoogle: true,
	OAuthProviderGitHub: true,
}

// IsValid returns true if the provider is in the supported set.
func (p OAuthProvider) IsValid() bool {
	return ValidOAuthProviders[p]
}

// String implements fmt.Stringer.
func (p OAuthProvider) String() string {
	return string(p)
}

// OAuthAccount links an external OAuth provider identity to a local user.
type OAuthAccount struct {
	ID             string
	UserID         string
	Provider       OAuthProvider
	ProviderUserID string
	Email          string
	AccessToken    string     // encrypted; never stored in plaintext
	RefreshToken   string     // encrypted; never stored in plaintext
	TokenExpiresAt *time.Time // when the provider access token expires
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

// OAuthUser is an intermediate type representing a user profile returned by
// an OAuth provider, before it is resolved to a local User.
type OAuthUser struct {
	Provider       OAuthProvider
	ProviderUserID string
	Email          string
	Name           string
	AvatarURL      string
	RawAttributes  map[string]interface{} // full provider payload for auditing
}

// --- Request / Response DTOs for OAuth endpoints ---

// OAuthAuthorizeRequest is the query-parameter input for the /oauth/:provider/authorize endpoint.
type OAuthAuthorizeRequest struct {
	Provider    OAuthProvider `form:"provider" binding:"required"`
	RedirectURI string        `form:"redirect_uri" binding:"required,url"`
	State       string        `form:"state" binding:"required"`
}

// OAuthCallbackRequest is the query-parameter input for the /oauth/:provider/callback endpoint.
type OAuthCallbackRequest struct {
	Provider OAuthProvider `form:"provider" binding:"required"`
	Code     string        `form:"code" binding:"required"`
	State    string        `form:"state" binding:"required"`
}

// OAuthTokenResponse is returned after a successful OAuth login or link.
type OAuthTokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// OAuthLinkRequest is the body for linking an OAuth provider to an existing user.
type OAuthLinkRequest struct {
	Provider    OAuthProvider `json:"provider" binding:"required"`
	Code        string        `json:"code" binding:"required"`
	RedirectURI string        `json:"redirect_uri" binding:"required,url"`
}

// OAuthUnlinkRequest is the body for unlinking an OAuth provider from a user.
type OAuthUnlinkRequest struct {
	Provider OAuthProvider `json:"provider" binding:"required"`
}

// OAuthAccountResponse is a user-facing representation of a linked OAuth account.
type OAuthAccountResponse struct {
	Provider       string    `json:"provider"`
	ProviderUserID string    `json:"provider_user_id"`
	Email          string    `json:"email"`
	LinkedAt       time.Time `json:"linked_at"`
}
