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

// GoogleProvider implements the Provider interface for Google OAuth2.
type GoogleProvider struct {
	cfg        *oauth2.Config
	httpClient *http.Client // injectable for testing; nil uses http.DefaultClient
}

// NewGoogleProvider creates a Google OAuth provider.
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

func (g *GoogleProvider) Name() domain.OAuthProvider {
	return domain.OAuthProviderGoogle
}

func (g *GoogleProvider) AuthCodeURL(state, codeVerifier string) string {
	challenge := CodeChallenge(codeVerifier)
	return g.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

// googleUserInfoURL is the Google userinfo endpoint. Package-level var for test injection.
var googleUserInfoURL = "https://www.googleapis.com/oauth2/v2/userinfo"

func (g *GoogleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*domain.OAuthUserInfo, error) {
	tok, err := g.cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("google token exchange: %w", err)
	}

	client := g.httpClient
	if client == nil {
		client = g.cfg.Client(ctx, tok)
	}

	resp, err := client.Get(googleUserInfoURL)
	if err != nil {
		return nil, fmt.Errorf("google userinfo request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("google userinfo returned %d: %s", resp.StatusCode, body)
	}

	var info struct {
		ID            string `json:"id"`
		Email         string `json:"email"`
		Name          string `json:"name"`
		VerifiedEmail bool   `json:"verified_email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("google userinfo decode: %w", err)
	}

	return &domain.OAuthUserInfo{
		ProviderUserID: info.ID,
		Email:          info.Email,
		Name:           info.Name,
		EmailVerified:  info.VerifiedEmail,
	}, nil
}
