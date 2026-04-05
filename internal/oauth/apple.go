package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/oauth2"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	appleAuthURL  = "https://appleid.apple.com/auth/authorize"
	appleTokenURL = "https://appleid.apple.com/auth/token"
	appleJWKSURL  = "https://appleid.apple.com/auth/keys"
	appleIssuer   = "https://appleid.apple.com"

	// Apple client_secret JWT lifetime.
	appleSecretTTL = 5 * time.Minute
)

// AppleProvider implements the Provider interface for Sign in with Apple.
// Apple does not expose a userinfo endpoint — user identity comes from the
// ID token returned during code exchange.
type AppleProvider struct {
	clientID   string
	teamID     string
	keyID      string
	privateKey *ecdsa.PrivateKey
	stateMgr   *StateManager
	httpClient *http.Client

	// redirectURI is sent during both auth URL generation and token exchange.
	redirectURI string

	// oauth2Cfg is used only for auth URL generation (PKCE + state).
	oauth2Cfg *oauth2.Config
}

// NewAppleProvider creates an Apple OAuth provider.
// cfg.ClientSecret is the path to the Apple .p8 private key file.
// cfg.TeamID and cfg.KeyID must be set (Apple Developer portal values).
func NewAppleProvider(cfg config.OAuthProviderConfig, stateMgr *StateManager, httpClient *http.Client) (*AppleProvider, error) {
	if cfg.TeamID == "" {
		return nil, fmt.Errorf("apple provider requires OAUTH_APPLE_TEAM_ID")
	}
	if cfg.KeyID == "" {
		return nil, fmt.Errorf("apple provider requires OAUTH_APPLE_KEY_ID")
	}

	key, err := loadApplePrivateKey(cfg.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("load apple private key: %w", err)
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	appleEndpoint := oauth2.Endpoint{
		AuthURL:   appleAuthURL,
		TokenURL:  appleTokenURL,
		AuthStyle: oauth2.AuthStyleInParams,
	}

	return &AppleProvider{
		clientID:    cfg.ClientID,
		teamID:      cfg.TeamID,
		keyID:       cfg.KeyID,
		privateKey:  key,
		stateMgr:    stateMgr,
		httpClient:  httpClient,
		redirectURI: cfg.RedirectURI,
		oauth2Cfg: &oauth2.Config{
			ClientID:    cfg.ClientID,
			RedirectURL: cfg.RedirectURI,
			Scopes:      []string{"name", "email"},
			Endpoint:    appleEndpoint,
		},
	}, nil
}

func (a *AppleProvider) Name() string { return "apple" }

func (a *AppleProvider) GetAuthURL(ctx context.Context) (string, error) {
	verifier := GenerateVerifier()

	state, err := a.stateMgr.Generate(verifier)
	if err != nil {
		return "", fmt.Errorf("generate state: %w", err)
	}

	authURL := a.oauth2Cfg.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	return authURL, nil
}

func (a *AppleProvider) ExchangeCode(ctx context.Context, code string) (*domain.OAuthUser, error) {
	verifier := CodeVerifierFromContext(ctx)

	clientSecret, err := a.generateClientSecret()
	if err != nil {
		return nil, fmt.Errorf("generate client secret: %w", err)
	}

	tokenResp, err := a.exchangeToken(ctx, code, clientSecret, verifier)
	if err != nil {
		return nil, fmt.Errorf("exchange token: %w", err)
	}

	claims, err := a.validateIDToken(ctx, tokenResp.IDToken)
	if err != nil {
		return nil, fmt.Errorf("validate id_token: %w", err)
	}

	return &domain.OAuthUser{
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
	}, nil
}

// appleTokenResponse holds the fields we need from Apple's token endpoint response.
type appleTokenResponse struct {
	IDToken string `json:"id_token"`
}

// appleIDClaims holds claims extracted from Apple's ID token.
type appleIDClaims struct {
	Subject string
	Email   string
}

// generateClientSecret creates a short-lived JWT signed with the Apple .p8 key.
// Apple uses this in place of a traditional client_secret.
func (a *AppleProvider) generateClientSecret() (string, error) {
	now := time.Now()
	claims := jwt.RegisteredClaims{
		Issuer:    a.teamID,
		Subject:   a.clientID,
		Audience:  jwt.ClaimStrings{appleIssuer},
		IssuedAt:  jwt.NewNumericDate(now),
		ExpiresAt: jwt.NewNumericDate(now.Add(appleSecretTTL)),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	token.Header["kid"] = a.keyID

	return token.SignedString(a.privateKey)
}

// exchangeToken performs the token exchange with Apple's token endpoint.
func (a *AppleProvider) exchangeToken(ctx context.Context, code, clientSecret, verifier string) (*appleTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {a.clientID},
		"client_secret": {clientSecret},
		"redirect_uri":  {a.redirectURI},
	}
	if verifier != "" {
		data.Set("code_verifier", verifier)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, appleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token endpoint returned %s: %s", resp.Status, body)
	}

	var tokenResp appleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}

	if tokenResp.IDToken == "" {
		return nil, fmt.Errorf("no id_token in response")
	}

	return &tokenResp, nil
}

// validateIDToken verifies the Apple ID token signature against Apple's JWKS
// and validates the standard claims.
func (a *AppleProvider) validateIDToken(ctx context.Context, idToken string) (*appleIDClaims, error) {
	keys, err := a.fetchJWKS(ctx)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}

	token, err := jwt.Parse(idToken, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok {
			return nil, fmt.Errorf("missing kid in token header")
		}

		for _, k := range keys {
			if k.KID == kid {
				return jwkToRSAPublicKey(k)
			}
		}
		return nil, fmt.Errorf("no matching key for kid %q", kid)
	}, jwt.WithValidMethods([]string{"RS256"}))
	if err != nil {
		return nil, fmt.Errorf("verify token: %w", err)
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token claims")
	}

	// Validate issuer and audience.
	iss, _ := claims.GetIssuer()
	if iss != appleIssuer {
		return nil, fmt.Errorf("invalid issuer: %s", iss)
	}
	aud, _ := claims.GetAudience()
	if !containsString(aud, a.clientID) {
		return nil, fmt.Errorf("invalid audience")
	}

	sub, _ := claims["sub"].(string)
	email, _ := claims["email"].(string)
	if sub == "" {
		return nil, fmt.Errorf("missing sub claim")
	}

	return &appleIDClaims{
		Subject: sub,
		Email:   email,
	}, nil
}

// appleJWK represents a single key from Apple's JWKS endpoint.
type appleJWK struct {
	KTY string `json:"kty"`
	KID string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func (a *AppleProvider) fetchJWKS(ctx context.Context) ([]appleJWK, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, appleJWKSURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create JWKS request: %w", err)
	}

	resp, err := a.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("JWKS request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read JWKS: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("JWKS endpoint returned %s", resp.Status)
	}

	var jwks struct {
		Keys []appleJWK `json:"keys"`
	}
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, fmt.Errorf("decode JWKS: %w", err)
	}

	return jwks.Keys, nil
}

// jwkToRSAPublicKey converts a JWK with RSA key type to an *rsa.PublicKey.
func jwkToRSAPublicKey(k appleJWK) (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("decode modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("decode exponent: %w", err)
	}

	n := new(big.Int).SetBytes(nBytes)
	e := int(new(big.Int).SetBytes(eBytes).Int64())

	return &rsa.PublicKey{N: n, E: e}, nil
}

// loadApplePrivateKey reads and parses an Apple .p8 ECDSA private key.
func loadApplePrivateKey(path string) (*ecdsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read key file: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in key file")
	}

	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse PKCS8 key: %w", err)
	}

	ecKey, ok := raw.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ECDSA (got %T)", raw)
	}

	return ecKey, nil
}

func containsString(ss []string, target string) bool {
	for _, s := range ss {
		if s == target {
			return true
		}
	}
	return false
}
