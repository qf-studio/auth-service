package oauth

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AppleProvider implements the Provider interface for Sign in with Apple.
// Apple uses a JWT-based client secret and returns user info via an ID token
// rather than a userinfo endpoint.
type AppleProvider struct {
	cfg        *oauth2.Config
	teamID     string
	keyID      string
	privateKey interface{} // *ecdsa.PrivateKey for ES256 signing
	httpClient *http.Client
	nowFunc    func() time.Time
}

// AppleConfig holds Apple-specific configuration beyond standard OAuth2 fields.
type AppleConfig struct {
	ClientID    string // Apple Services ID (e.g., "com.example.app")
	TeamID      string // Apple Developer Team ID
	KeyID       string // Key ID for the private key
	PrivateKey  interface{}
	RedirectURL string
}

// appleAuthURL and appleTokenURL are Apple's OAuth endpoints.
var (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleKeysURL  = "https://appleid.apple.com/auth/keys"
)

// NewAppleProvider creates an Apple Sign In provider.
func NewAppleProvider(cfg AppleConfig) *AppleProvider {
	return &AppleProvider{
		cfg: &oauth2.Config{
			ClientID: cfg.ClientID,
			Endpoint: oauth2.Endpoint{
				AuthURL:  appleAuthURL,
				TokenURL: appleTokenURL,
			},
			RedirectURL: cfg.RedirectURL,
			Scopes:      []string{"name", "email"},
		},
		teamID:     cfg.TeamID,
		keyID:      cfg.KeyID,
		privateKey: cfg.PrivateKey,
		nowFunc:    time.Now,
	}
}

func (a *AppleProvider) Name() domain.OAuthProvider {
	return domain.OAuthProviderApple
}

func (a *AppleProvider) AuthCodeURL(state, codeVerifier string) string {
	challenge := CodeChallenge(codeVerifier)
	return a.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("response_mode", "form_post"),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

func (a *AppleProvider) ExchangeCode(ctx context.Context, code, codeVerifier string) (*domain.OAuthUserInfo, error) {
	// Generate the ephemeral client_secret JWT.
	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("apple generate client secret: %w", err)
	}

	// Override client secret for this exchange.
	cfg := *a.cfg
	cfg.ClientSecret = clientSecret

	tok, err := cfg.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", codeVerifier),
	)
	if err != nil {
		return nil, fmt.Errorf("apple token exchange: %w", err)
	}

	// Apple returns user info in the id_token, not via a separate endpoint.
	idTokenRaw, ok := tok.Extra("id_token").(string)
	if !ok || idTokenRaw == "" {
		return nil, errors.New("apple: no id_token in token response")
	}

	info, err := a.parseIDToken(ctx, idTokenRaw)
	if err != nil {
		return nil, fmt.Errorf("apple parse id_token: %w", err)
	}

	return info, nil
}

// generateClientSecret creates a short-lived ES256 JWT used as the client_secret
// when calling Apple's token endpoint.
func (a *AppleProvider) generateClientSecret() (string, error) {
	now := a.nowFunc()
	claims := jwt.RegisteredClaims{
		Issuer:    a.teamID,
		Subject:   a.cfg.ClientID,
		Audience:  jwt.ClaimStrings{"https://appleid.apple.com"},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(5 * time.Minute)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.keyID

	signed, err := token.SignedString(a.privateKey)
	if err != nil {
		return "", fmt.Errorf("sign client secret: %w", err)
	}
	return signed, nil
}

// parseIDToken validates and extracts user info from Apple's id_token.
// It fetches Apple's public keys and verifies the JWT signature.
func (a *AppleProvider) parseIDToken(ctx context.Context, rawToken string) (*domain.OAuthUserInfo, error) {
	keys, err := a.fetchApplePublicKeys(ctx)
	if err != nil {
		return nil, err
	}

	token, err := jwt.Parse(rawToken, func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("missing kid in id_token header")
		}
		key, exists := keys[kid]
		if !exists {
			return nil, fmt.Errorf("unknown kid %q in id_token", kid)
		}
		return key, nil
	},
		jwt.WithValidMethods([]string{"RS256"}),
		jwt.WithIssuer("https://appleid.apple.com"),
		jwt.WithAudience(a.cfg.ClientID),
	)
	if err != nil {
		return nil, fmt.Errorf("validate id_token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid id_token claims")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	emailVerified, _ := claims["email_verified"].(bool)
	// If email_verified comes as a string "true", handle it.
	if !emailVerified {
		if ev, ok := claims["email_verified"].(string); ok && ev == "true" {
			emailVerified = true
		}
	}

	return &domain.OAuthUserInfo{
		ProviderUserID: sub,
		Email:          email,
		Name:           "", // Apple only provides name on first authorization; handled at service level.
		EmailVerified:  emailVerified,
	}, nil
}

// appleJWKSet represents the response from Apple's keys endpoint.
type appleJWKSet struct {
	Keys []appleJWK `json:"keys"`
}

type appleJWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// fetchApplePublicKeys retrieves Apple's JWKS and returns a map of kid → *rsa.PublicKey.
func (a *AppleProvider) fetchApplePublicKeys(ctx context.Context) (map[string]*rsa.PublicKey, error) {
	client := a.httpClient
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleKeysURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create apple keys request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch apple keys: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("apple keys returned %d: %s", resp.StatusCode, body)
	}

	var jwks appleJWKSet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("decode apple keys: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(jwks.Keys))
	for _, k := range jwks.Keys {
		if k.Kty != "RSA" || k.Use != "sig" {
			continue
		}
		pub, err := jwkToRSAPublicKey(k)
		if err != nil {
			continue
		}
		keys[k.Kid] = pub
	}

	return keys, nil
}

// jwkToRSAPublicKey converts a JWK to an *rsa.PublicKey.
func jwkToRSAPublicKey(k appleJWK) (*rsa.PublicKey, error) {
	nBytes, err := jwt.NewParser().DecodeSegment(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode n: %w", err)
	}
	eBytes, err := jwt.NewParser().DecodeSegment(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode e: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := new(big.Int).SetBytes(eBytes)

	return &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}, nil
}
