package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	githubAuthURL  = "https://github.com/login/oauth/authorize"
	githubTokenURL = "https://github.com/login/oauth/access_token"
	githubUserURL  = "https://api.github.com/user"
)

// GitHubProvider implements the Provider interface for GitHub OAuth.
type GitHubProvider struct {
	cfg        config.OAuthProviderConfig
	httpClient *http.Client
	stateGen   StateGenerator
	tokenURL   string
	userURL    string
}

// NewGitHubProvider creates a new GitHub OAuth provider.
func NewGitHubProvider(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator) *GitHubProvider {
	return &GitHubProvider{
		cfg:        cfg,
		httpClient: httpClient,
		stateGen:   stateGen,
		tokenURL:   githubTokenURL,
		userURL:    githubUserURL,
	}
}

// NewGitHubProviderWithURLs creates a GitHub provider with custom endpoint URLs (for testing).
func NewGitHubProviderWithURLs(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator, tokenURL, userURL string) *GitHubProvider {
	return &GitHubProvider{
		cfg:        cfg,
		httpClient: httpClient,
		stateGen:   stateGen,
		tokenURL:   tokenURL,
		userURL:    userURL,
	}
}

// Name returns "github".
func (p *GitHubProvider) Name() string { return "github" }

// GetAuthURL returns the GitHub OAuth authorization URL.
func (p *GitHubProvider) GetAuthURL(ctx context.Context) (string, error) {
	state, err := p.stateGen.Generate()
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	params := url.Values{
		"client_id":    {p.cfg.ClientID},
		"redirect_uri": {p.cfg.RedirectURI},
		"scope":        {"read:user user:email"},
		"state":        {state},
	}

	return githubAuthURL + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for GitHub user information.
func (p *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	// Exchange code for token.
	data := url.Values{
		"code":          {code},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"redirect_uri":  {p.cfg.RedirectURI},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := p.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed with status %d", resp.StatusCode)
	}

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	if tokenResp.Error != "" {
		return nil, fmt.Errorf("token exchange error: %s", tokenResp.Error)
	}

	// Fetch user info.
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create user request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/json")

	userResp, err := p.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("user request: %w", err)
	}
	defer func() { _ = userResp.Body.Close() }()

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("user request failed with status %d", userResp.StatusCode)
	}

	var userInfo struct {
		ID    int64  `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Login string `json:"login"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decode user response: %w", err)
	}

	name := userInfo.Name
	if name == "" {
		name = userInfo.Login
	}

	return &domain.OAuthUser{
		ProviderUserID: fmt.Sprintf("%d", userInfo.ID),
		Email:          userInfo.Email,
		Name:           name,
	}, nil
}
