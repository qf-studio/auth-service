package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"golang.org/x/oauth2"
	oauthgithub "golang.org/x/oauth2/github"

	"github.com/qf-studio/auth-service/internal/domain"
)

// GitHubProvider implements the Provider interface for GitHub OAuth2.
type GitHubProvider struct {
	cfg        *oauth2.Config
	httpClient *http.Client // injectable for testing; nil uses http.DefaultClient
}

// NewGitHubProvider creates a GitHub OAuth provider.
func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"user:email"},
			Endpoint:     oauthgithub.Endpoint,
		},
	}
}

func (g *GitHubProvider) Name() domain.OAuthProvider {
	return domain.OAuthProviderGitHub
}

func (g *GitHubProvider) AuthCodeURL(state, codeVerifier string) string {
	// GitHub doesn't support PKCE but we keep the interface consistent.
	// The code_verifier is still used on the exchange side.
	return g.cfg.AuthCodeURL(state)
}

// githubUserURL and githubEmailsURL are the GitHub API endpoints. Package-level vars for test injection.
var (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

func (g *GitHubProvider) ExchangeCode(ctx context.Context, code, _ string) (*domain.OAuthUserInfo, error) {
	tok, err := g.cfg.Exchange(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("github token exchange: %w", err)
	}

	client := g.httpClient
	if client == nil {
		client = g.cfg.Client(ctx, tok)
	}

	// Fetch user profile.
	userResp, err := client.Get(githubUserURL)
	if err != nil {
		return nil, fmt.Errorf("github user request: %w", err)
	}
	defer userResp.Body.Close()

	if userResp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(userResp.Body)
		return nil, fmt.Errorf("github user returned %d: %s", userResp.StatusCode, body)
	}

	var user struct {
		ID    int    `json:"id"`
		Name  string `json:"name"`
		Login string `json:"login"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&user); err != nil {
		return nil, fmt.Errorf("github user decode: %w", err)
	}

	name := user.Name
	if name == "" {
		name = user.Login
	}

	email := user.Email
	emailVerified := false

	// If the profile email is empty, fetch from the emails endpoint.
	if email == "" {
		email, emailVerified, err = g.fetchPrimaryEmail(client)
		if err != nil {
			return nil, err
		}
	} else {
		// Verify the profile email via the emails endpoint.
		emailVerified, _ = g.checkEmailVerified(client, email)
	}

	return &domain.OAuthUserInfo{
		ProviderUserID: strconv.Itoa(user.ID),
		Email:          email,
		Name:           name,
		EmailVerified:  emailVerified,
	}, nil
}

// fetchPrimaryEmail retrieves the user's primary verified email from GitHub.
func (g *GitHubProvider) fetchPrimaryEmail(client *http.Client) (string, bool, error) {
	resp, err := client.Get(githubEmailsURL)
	if err != nil {
		return "", false, fmt.Errorf("github emails request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", false, fmt.Errorf("github emails returned %d: %s", resp.StatusCode, body)
	}

	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return "", false, fmt.Errorf("github emails decode: %w", err)
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, true, nil
		}
	}
	for _, e := range emails {
		if e.Primary {
			return e.Email, e.Verified, nil
		}
	}
	if len(emails) > 0 {
		return emails[0].Email, emails[0].Verified, nil
	}

	return "", false, fmt.Errorf("github: no email addresses found")
}

// checkEmailVerified checks if a specific email is verified via the emails endpoint.
func (g *GitHubProvider) checkEmailVerified(client *http.Client, targetEmail string) (bool, error) {
	resp, err := client.Get(githubEmailsURL)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, nil
	}

	var emails []struct {
		Email    string `json:"email"`
		Verified bool   `json:"verified"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&emails); err != nil {
		return false, nil
	}

	for _, e := range emails {
		if e.Email == targetEmail {
			return e.Verified, nil
		}
	}
	return false, nil
}
