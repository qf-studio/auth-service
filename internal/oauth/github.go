package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	githubUserURL   = "https://api.github.com/user"
	githubEmailsURL = "https://api.github.com/user/emails"
)

var githubEndpoint = oauth2.Endpoint{
	AuthURL:   "https://github.com/login/oauth/authorize",
	TokenURL:  "https://github.com/login/oauth/access_token",
	AuthStyle: oauth2.AuthStyleInParams,
}

// GitHubProvider implements the Provider interface for GitHub OAuth 2.0.
type GitHubProvider struct {
	oauth2Cfg  *oauth2.Config
	stateMgr   *StateManager
	httpClient *http.Client
}

// NewGitHubProvider creates a GitHub OAuth provider.
func NewGitHubProvider(cfg config.OAuthProviderConfig, stateMgr *StateManager, httpClient *http.Client) *GitHubProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &GitHubProvider{
		oauth2Cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       []string{"read:user", "user:email"},
			Endpoint:     githubEndpoint,
		},
		stateMgr:   stateMgr,
		httpClient: httpClient,
	}
}

func (g *GitHubProvider) Name() string { return "github" }

func (g *GitHubProvider) GetAuthURL(ctx context.Context) (string, error) {
	verifier := GenerateVerifier()

	state, err := g.stateMgr.Generate(verifier)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	url := g.oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return url, nil
}

func (g *GitHubProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	verifier := CodeVerifierFromContext(ctx)

	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.httpClient)
	token, err := g.oauth2Cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	return g.fetchUser(ctx, token)
}

func (g *GitHubProvider) fetchUser(ctx context.Context, token *oauth2.Token) (*domain.OAuthUser, error) {
	var profile struct {
		ID    int64  `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := g.apiGet(ctx, token, githubUserURL, &profile); err != nil {
		return nil, fmt.Errorf("fetch user profile: %w", err)
	}

	email := profile.Email
	if email == "" {
		// GitHub hides primary email if it's private; fetch from emails endpoint.
		primary, err := g.fetchPrimaryEmail(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("fetch primary email: %w", err)
		}
		email = primary
	}

	return &domain.OAuthUser{
		ProviderUserID: fmt.Sprintf("%d", profile.ID),
		Email:          email,
		Name:           profile.Name,
	}, nil
}

func (g *GitHubProvider) fetchPrimaryEmail(ctx context.Context, token *oauth2.Token) (string, error) {
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.apiGet(ctx, token, githubEmailsURL, &emails); err != nil {
		return "", err
	}

	for _, e := range emails {
		if e.Primary && e.Verified {
			return e.Email, nil
		}
	}
	return "", fmt.Errorf("no verified primary email found")
}

func (g *GitHubProvider) apiGet(ctx context.Context, token *oauth2.Token, url string, dest interface{}) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	token.SetAuthHeader(req)
	req.Header.Set("Accept", "application/json")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read body: %w", err)
	}

	if err := json.Unmarshal(body, dest); err != nil {
		return fmt.Errorf("decode body: %w", err)
	}
	return nil
}
