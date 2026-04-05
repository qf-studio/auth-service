package oauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestAppleProvider_Name(t *testing.T) {
	p := NewAppleProvider(AppleConfig{ClientID: "com.example.app"})
	assert.Equal(t, domain.OAuthProviderApple, p.Name())
}

func TestAppleProvider_AuthCodeURL(t *testing.T) {
	p := NewAppleProvider(AppleConfig{
		ClientID:    "com.example.app",
		RedirectURL: "https://example.com/callback",
	})

	url := p.AuthCodeURL("test-state", "test-verifier")
	assert.Contains(t, url, "state=test-state")
	assert.Contains(t, url, "response_mode=form_post")
	assert.Contains(t, url, "code_challenge=")
	assert.Contains(t, url, "code_challenge_method=S256")
}

func TestAppleProvider_GenerateClientSecret(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p := NewAppleProvider(AppleConfig{
		ClientID: "com.example.app",
		TeamID:   "TEAM123",
		KeyID:    "KEY456",
	})
	p.privateKey = key
	now := time.Now()
	p.nowFunc = func() time.Time { return now }

	secret, err := p.generateClientSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Parse and validate the generated JWT.
	token, err := jwt.Parse(secret, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, token.Valid)

	claims, ok := token.Claims.(jwt.MapClaims)
	require.True(t, ok)

	assert.Equal(t, "TEAM123", claims["iss"])
	assert.Equal(t, "com.example.app", claims["sub"])
	assert.Equal(t, "KEY456", token.Header["kid"])
}

func TestAppleProvider_ExchangeCode_Success(t *testing.T) {
	// Generate RSA key pair for signing the mock id_token.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	kid := "test-kid-1"

	// Create a mock id_token.
	idTokenClaims := jwt.MapClaims{
		"iss":            "https://appleid.apple.com",
		"aud":            "com.example.app",
		"sub":            "apple-user-001",
		"email":          "user@icloud.com",
		"email_verified": true,
		"iat":            time.Now().Unix(),
		"exp":            time.Now().Add(time.Hour).Unix(),
	}
	idToken := jwt.NewWithClaims(jwt.SigningMethodRS256, idTokenClaims)
	idToken.Header["kid"] = kid
	idTokenStr, err := idToken.SignedString(rsaKey)
	require.NoError(t, err)

	// Mock Apple keys endpoint.
	keysServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		nBytes := rsaKey.PublicKey.N.Bytes()
		eBytes := big.NewInt(int64(rsaKey.PublicKey.E)).Bytes()
		jwks := map[string]interface{}{
			"keys": []map[string]interface{}{
				{
					"kty": "RSA",
					"kid": kid,
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(nBytes),
					"e":   base64.RawURLEncoding.EncodeToString(eBytes),
				},
			},
		}
		_ = json.NewEncoder(w).Encode(jwks)
	}))
	defer keysServer.Close()

	// Mock token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := map[string]interface{}{
			"access_token": "test-token",
			"token_type":   "Bearer",
			"id_token":     idTokenStr,
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer tokenServer.Close()

	// Override Apple URLs.
	origKeysURL := appleKeysURL
	appleKeysURL = keysServer.URL
	defer func() { appleKeysURL = origKeysURL }()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p := NewAppleProvider(AppleConfig{
		ClientID:    "com.example.app",
		TeamID:      "TEAM123",
		KeyID:       "KEY456",
		PrivateKey:  ecKey,
		RedirectURL: "https://example.com/callback",
	})
	p.cfg.Endpoint.TokenURL = tokenServer.URL
	p.httpClient = &http.Client{}

	info, err := p.ExchangeCode(t.Context(), "auth-code", "verifier")
	require.NoError(t, err)
	assert.Equal(t, "apple-user-001", info.ProviderUserID)
	assert.Equal(t, "user@icloud.com", info.Email)
	assert.True(t, info.EmailVerified)
}

func TestAppleProvider_ExchangeCode_TokenError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	p := NewAppleProvider(AppleConfig{
		ClientID:   "com.example.app",
		TeamID:     "TEAM123",
		KeyID:      "KEY456",
		PrivateKey: ecKey,
	})
	p.cfg.Endpoint.TokenURL = tokenServer.URL

	_, err = p.ExchangeCode(t.Context(), "bad-code", "verifier")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "apple token exchange")
}

func TestJwkToRSAPublicKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	nBytes := key.PublicKey.N.Bytes()
	eBytes := big.NewInt(int64(key.PublicKey.E)).Bytes()

	jwk := appleJWK{
		Kty: "RSA",
		Kid: "test",
		Use: "sig",
		Alg: "RS256",
		N:   base64.RawURLEncoding.EncodeToString(nBytes),
		E:   base64.RawURLEncoding.EncodeToString(eBytes),
	}

	pub, err := jwkToRSAPublicKey(jwk)
	require.NoError(t, err)
	assert.Equal(t, key.PublicKey.N, pub.N)
	assert.Equal(t, key.PublicKey.E, pub.E)
}
