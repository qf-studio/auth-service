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
	googleAuthURL     = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL    = "https://oauth2.googleapis.com/token"
	googleUserInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
)

// GoogleProvider implements the Provider interface for Google OAuth.
type GoogleProvider struct {
	cfg          config.OAuthProviderConfig
	httpClient   *http.Client
	stateGen     StateGenerator
	tokenURL     string
	userInfoURL  string
}

// NewGoogleProvider creates a new Google OAuth provider.
func NewGoogleProvider(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator) *GoogleProvider {
	return &GoogleProvider{
		cfg:         cfg,
		httpClient:  httpClient,
		stateGen:    stateGen,
		tokenURL:    googleTokenURL,
		userInfoURL: googleUserInfoURL,
	}
}

// NewGoogleProviderWithURLs creates a Google provider with custom endpoint URLs (for testing).
func NewGoogleProviderWithURLs(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator, tokenURL, userInfoURL string) *GoogleProvider {
	return &GoogleProvider{
		cfg:         cfg,
		httpClient:  httpClient,
		stateGen:    stateGen,
		tokenURL:    tokenURL,
		userInfoURL: userInfoURL,
	}
}

// Name returns "google".
func (p *GoogleProvider) Name() string { return "google" }

// GetAuthURL returns the Google OAuth authorization URL.
func (p *GoogleProvider) GetAuthURL(ctx context.Context) (string, error) {
	state, err := p.stateGen.Generate()
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	params := url.Values{
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURI},
		"response_type": {"code"},
		"scope":         {"openid email profile"},
		"state":         {state},
		"access_type":   {"offline"},
	}

	return googleAuthURL + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for Google user information.
func (p *GoogleProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	// Exchange code for tokens.
	data := url.Values{
		"code":          {code},
		"client_id":     {p.cfg.ClientID},
		"client_secret": {p.cfg.ClientSecret},
		"redirect_uri":  {p.cfg.RedirectURI},
		"grant_type":    {"authorization_code"},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.tokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

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
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	// Fetch user info.
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create userinfo request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := p.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("userinfo request: %w", err)
	}
	defer func() { _ = userResp.Body.Close() }()

	if userResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("userinfo request failed with status %d", userResp.StatusCode)
	}

	var userInfo struct {
		Sub   string `json:"sub"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(userResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("decode userinfo response: %w", err)
	}

	return &domain.OAuthUser{
		ProviderUserID: userInfo.Sub,
		Email:          userInfo.Email,
		Name:           userInfo.Name,
	}, nil
}
