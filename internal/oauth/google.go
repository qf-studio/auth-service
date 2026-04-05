package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/qf-studio/auth-service/internal/domain"
)

const googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

// GoogleProvider implements Provider for Google OAuth 2.0.
type GoogleProvider struct {
	cfg *oauth2.Config
}

// NewGoogleProvider creates a Google OAuth provider with the given credentials.
func NewGoogleProvider(clientID, clientSecret, redirectURL string) *GoogleProvider {
	return &GoogleProvider{
		cfg: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  redirectURL,
			Scopes:       []string{"openid", "email", "profile"},
			Endpoint:     google.Endpoint,
		},
	}
}

func (p *GoogleProvider) Name() domain.OAuthProviderType {
	return domain.OAuthProviderGoogle
}

func (p *GoogleProvider) GetAuthURL(state, codeChallenge string) string {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.AccessTypeOffline,
	}
	return p.cfg.AuthCodeURL(state, opts...)
}

func (p *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	opts := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	}
	token, err := p.cfg.Exchange(ctx, code, opts...)
	if err != nil {
		return "", fmt.Errorf("google code exchange: %w", err)
	}
	return token.AccessToken, nil
}

func (p *GoogleProvider) GetUser(ctx context.Context, accessToken string) (*domain.OAuthUser, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, googleUserInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create google userinfo request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("google userinfo request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo: status %d: %s", resp.StatusCode, body)
	}

	var info struct {
		ID      string `json:"id"`
		Email   string `json:"email"`
		Name    string `json:"name"`
		Picture string `json:"picture"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("decode google userinfo: %w", err)
	}

	return &domain.OAuthUser{
		ProviderUserID: info.ID,
		Email:          info.Email,
		Name:           info.Name,
		AvatarURL:      info.Picture,
	}, nil
}
