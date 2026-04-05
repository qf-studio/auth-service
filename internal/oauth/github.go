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

const githubUserURL = "https://api.github.com/user"

// GitHubProvider implements Provider for GitHub OAuth.
type GitHubProvider struct {
	cfg *oauth2.Config
}

// NewGitHubProvider creates a GitHub OAuth provider with the given credentials.
func NewGitHubProvider(clientID, clientSecret, redirectURL string) *GitHubProvider {
	return &GitHubProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     oauthgithub.Endpoint,
		},
	}
}

func (p *GitHubProvider) Name() domain.OAuthProviderType {
	return domain.OAuthProviderGitHub
}

func (p *GitHubProvider) GetAuthURL(state, codeChallenge string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	}
	return p.cfg.AuthCodeURL(state, opts...)
}

func (p *GitHubProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
	token, err := p.cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return "", fmt.Errorf("github code exchange: %w", err)
	}
	return token.AccessToken, nil
}

func (p *GitHubProvider) GetUser(ctx context.Context, accessToken string) (*domain.OAuthUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, githubUserURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create github user request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("github user request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("github user: status %d: %s", resp.StatusCode, body)
	}

	var info struct {
		ID        int    `json:"id"`
		Login     string `json:"login"`
		Email     string `json:"email"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode github user: %w", err)
	}

	return &domain.OAuthUser{
		ProviderUserID: strconv.Itoa(info.ID),
		Email:          info.Email,
		Name:           info.Name,
		AvatarURL:      info.AvatarURL,
	}, nil
}
