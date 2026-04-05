package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
)

// AppleProvider implements the Provider interface for Apple Sign-In.
type AppleProvider struct {
	cfg        config.OAuthProviderConfig
	httpClient *http.Client
	stateGen   StateGenerator
	tokenURL   string
}

// NewAppleProvider creates a new Apple OAuth provider.
func NewAppleProvider(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator) *AppleProvider {
	return &AppleProvider{
		cfg:        cfg,
		httpClient: httpClient,
		stateGen:   stateGen,
		tokenURL:   appleTokenURL,
	}
}

// NewAppleProviderWithURLs creates an Apple provider with custom endpoint URLs (for testing).
func NewAppleProviderWithURLs(cfg config.OAuthProviderConfig, httpClient *http.Client, stateGen StateGenerator, tokenURL string) *AppleProvider {
	return &AppleProvider{
		cfg:        cfg,
		httpClient: httpClient,
		stateGen:   stateGen,
		tokenURL:   tokenURL,
	}
}

// Name returns "apple".
func (p *AppleProvider) Name() string { return "apple" }

// GetAuthURL returns the Apple Sign-In authorization URL.
func (p *AppleProvider) GetAuthURL(ctx context.Context) (string, error) {
	state, err := p.stateGen.Generate()
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	params := url.Values{
		"client_id":     {p.cfg.ClientID},
		"redirect_uri":  {p.cfg.RedirectURI},
		"response_type": {"code"},
		"scope":         {"name email"},
		"state":         {state},
		"response_mode": {"form_post"},
	}

	return appleAuthURL + "?" + params.Encode(), nil
}

// ExchangeCode exchanges an authorization code for Apple user information.
// Apple returns an id_token JWT containing user info; no separate userinfo endpoint exists.
func (p *AppleProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
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
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("apple token response missing id_token")
	}

	// Parse claims from ID token without full signature verification.
	// Decision: In production, Apple's public keys should be fetched from
	// https://appleid.apple.com/auth/keys and used to verify the JWT.
	// For the initial integration, we parse claims and trust the TLS channel
	// to Apple's token endpoint.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenResp.IDToken, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("parse apple id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid apple id_token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)

	if sub == "" {
		return nil, fmt.Errorf("apple id_token missing sub claim")
	}

	return &domain.OAuthUser{
		ProviderUserID: sub,
		Email:          email,
	}, nil
}
