package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
)

// AppleProvider implements Provider for Sign in with Apple.
// Apple uses JWT-based client authentication instead of a simple client secret.
type AppleProvider struct {
	clientID    string
	teamID      string
	keyID       string
	privateKey  *rsa.PrivateKey
	redirectURL string
}

// AppleProviderConfig holds the config needed for Apple's JWT client auth.
type AppleProviderConfig struct {
	ClientID    string
	TeamID      string
	KeyID       string
	PrivateKey  *rsa.PrivateKey
	RedirectURL string
}

// NewAppleProvider creates a Sign in with Apple provider.
func NewAppleProvider(cfg AppleProviderConfig) *AppleProvider {
	return &AppleProvider{
		clientID:    cfg.ClientID,
		teamID:      cfg.TeamID,
		keyID:       cfg.KeyID,
		privateKey:  cfg.PrivateKey,
		redirectURL: cfg.RedirectURL,
	}
}

func (p *AppleProvider) Name() domain.OAuthProviderType {
	return domain.OAuthProviderApple
}

func (p *AppleProvider) GetAuthURL(state, codeChallenge string) string {
	params := url.Values{
		"client_id":             {p.clientID},
		"redirect_uri":         {p.redirectURL},
		"response_type":        {"code"},
		"scope":                {"name email"},
		"response_mode":        {"form_post"},
		"state":                {state},
		"code_challenge":       {codeChallenge},
		"code_challenge_method": {"S256"},
	}
	return appleAuthURL + "?" + params.Encode()
}

func (p *AppleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (string, error) {
	clientSecret, err := p.generateClientSecret()
	if err != nil {
		return "", fmt.Errorf("generate apple client secret: %w", err)
	}

	data := url.Values{
		"client_id":     {p.clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"grant_type":    {"authorization_code"},
		"redirect_uri":  {p.redirectURL},
		"code_verifier": {codeVerifier},
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("create apple token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("apple token request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("apple token: status %d: %s", resp.StatusCode, body)
	}

	var tokenResp struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decode apple token response: %w", err)
	}

	return tokenResp.IDToken, nil
}

// GetUser extracts user info from the Apple ID token (JWT).
// Apple returns user info in the id_token, not a separate userinfo endpoint.
func (p *AppleProvider) GetUser(_ context.Context, idToken string) (*domain.OAuthUser, error) {
	// Parse without verification — the token was just received over TLS from Apple's token endpoint.
	// In production, you should verify against Apple's public keys.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(idToken, jwt.MapClaims{})
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

// generateClientSecret creates a short-lived JWT signed with the Apple private key.
func (p *AppleProvider) generateClientSecret() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    p.teamID,
		Subject:   p.clientID,
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = p.keyID

	signed, err := token.SignedString(p.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign apple client secret: %w", err)
	}
	return signed, nil
}
