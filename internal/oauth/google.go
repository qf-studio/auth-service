package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

// GoogleProvider implements the Provider interface for Google OAuth 2.0.
type GoogleProvider struct {
	oauth2Cfg  *oauth2.Config
	stateMgr   *StateManager
	httpClient *http.Client
}

// NewGoogleProvider creates a Google OAuth provider.
func NewGoogleProvider(cfg config.OAuthProviderConfig, stateMgr *StateManager, httpClient *http.Client) *GoogleProvider {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &GoogleProvider{
		oauth2Cfg: &oauth2.Config{
			ClientID:     cfg.ClientID,
			ClientSecret: cfg.ClientSecret,
			RedirectURL:  cfg.RedirectURI,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
		stateMgr:   stateMgr,
		httpClient: httpClient,
	}
}

func (g *GoogleProvider) Name() string { return "google" }

func (g *GoogleProvider) GetAuthURL(ctx context.Context) (string, error) {
	verifier := GenerateVerifier()

	state, err := g.stateMgr.Generate(verifier)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	url := g.oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return url, nil
}

func (g *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	verifier := CodeVerifierFromContext(ctx)

	opts := []oauth2.AuthCodeOption{oauth2.VerifierOption(verifier)}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.httpClient)
	token, err := g.oauth2Cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}

	return g.fetchUserInfo(ctx, token)
}

func (g *GoogleProvider) fetchUserInfo(ctx context.Context, token *oauth2.Token) (*domain.OAuthUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	token.SetAuthHeader(req)

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo response: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read userinfo body: %w", err)
	}

	var info struct {
		ID    string `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("decode userinfo: %w", err)
	}

	return &domain.OAuthUser{
		ProviderUserID: info.ID,
		Email:          info.Email,
		Name:           info.Name,
	}, nil
}
