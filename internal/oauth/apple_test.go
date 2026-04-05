package oauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
)

// writeTestP8Key generates an ECDSA P-256 key, writes it to a temp file,
// and returns the file path and the key.
func writeTestP8Key(t *testing.T) (string, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)

	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}
	path := filepath.Join(t.TempDir(), "apple.p8")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(block), 0600))

	return path, key
}

// generateTestRSAKey creates an RSA key pair for mocking Apple's JWKS.
func generateTestRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// buildTestIDToken creates a signed ID token using the given RSA key.
func buildTestIDToken(t *testing.T, rsaKey *rsa.PrivateKey, kid, clientID, sub, email string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"iss":   appleIssuer,
		"aud":   clientID,
		"sub":   sub,
		"email": email,
		"exp":   time.Now().Add(time.Hour).Unix(),
		"iat":   time.Now().Unix(),
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid

	signed, err := token.SignedString(rsaKey)
	require.NoError(t, err)
	return signed
}

// buildJWKSResponse builds a JWKS JSON response from an RSA public key.
func buildJWKSResponse(t *testing.T, key *rsa.PublicKey, kid string) []byte {
	t.Helper()
	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"kid": kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			},
		},
	}
	data, err := json.Marshal(jwks)
	require.NoError(t, err)
	return data
}

func newTestAppleProvider(t *testing.T, tokenURL, jwksURL string) *AppleProvider {
	t.Helper()
	keyPath, ecKey := writeTestP8Key(t)
	stateMgr := NewStateManager(testSecret)
	cfg := config.OAuthProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: keyPath,
		RedirectURI:  "http://localhost/callback",
		Enabled:      true,
		TeamID:       "TEAM123",
		KeyID:        "KEY456",
	}
	p, err := NewAppleProvider(cfg, stateMgr, nil)
	require.NoError(t, err)

	// Replace endpoints for testing.
	p.oauth2Cfg.Endpoint.AuthURL = "https://appleid.apple.com/auth/authorize"
	// Store the key directly (already loaded from file).
	_ = ecKey
	// We'll override httpClient in specific tests.

	return p
}

func TestAppleProvider_Name(t *testing.T) {
	keyPath, _ := writeTestP8Key(t)
	cfg := config.OAuthProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: keyPath,
		TeamID:       "T",
		KeyID:        "K",
		Enabled:      true,
	}
	p, err := NewAppleProvider(cfg, NewStateManager("s"), nil)
	require.NoError(t, err)
	assert.Equal(t, "apple", p.Name())
}

func TestAppleProvider_NewAppleProvider_MissingTeamID(t *testing.T) {
	keyPath, _ := writeTestP8Key(t)
	cfg := config.OAuthProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: keyPath,
		KeyID:        "K",
		Enabled:      true,
	}
	_, err := NewAppleProvider(cfg, NewStateManager("s"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "TEAM_ID")
}

func TestAppleProvider_NewAppleProvider_MissingKeyID(t *testing.T) {
	keyPath, _ := writeTestP8Key(t)
	cfg := config.OAuthProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: keyPath,
		TeamID:       "T",
		Enabled:      true,
	}
	_, err := NewAppleProvider(cfg, NewStateManager("s"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "KEY_ID")
}

func TestAppleProvider_NewAppleProvider_BadKeyPath(t *testing.T) {
	cfg := config.OAuthProviderConfig{
		ClientID:     "com.example.app",
		ClientSecret: "/nonexistent/path.p8",
		TeamID:       "T",
		KeyID:        "K",
		Enabled:      true,
	}
	_, err := NewAppleProvider(cfg, NewStateManager("s"), nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "private key")
}

func TestAppleProvider_GetAuthURL(t *testing.T) {
	p := newTestAppleProvider(t, "", "")

	authURL, err := p.GetAuthURL(context.Background())
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)

	q := parsed.Query()
	assert.Equal(t, "com.example.app", q.Get("client_id"))
	assert.NotEmpty(t, q.Get("state"))
	assert.NotEmpty(t, q.Get("code_challenge"))
	assert.Equal(t, "S256", q.Get("code_challenge_method"))
}

func TestAppleProvider_ExchangeCode(t *testing.T) {
	rsaKey := generateTestRSAKey(t)
	kid := "apple-kid-1"
	clientID := "com.example.app"
	idToken := buildTestIDToken(t, rsaKey, kid, clientID, "apple-user-001", "user@icloud.com")
	jwksData := buildJWKSResponse(t, &rsaKey.PublicKey, kid)

	// Mock Apple token endpoint.
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "POST", r.Method)
		assert.NoError(t, r.ParseForm())
		assert.Equal(t, "authorization_code", r.FormValue("grant_type"))
		assert.Equal(t, clientID, r.FormValue("client_id"))
		assert.NotEmpty(t, r.FormValue("client_secret"))
		assert.NotEmpty(t, r.FormValue("code_verifier"))

		w.Header().Set("Content-Type", "application/json")
		resp, _ := json.Marshal(map[string]string{
			"id_token": idToken,
		})
		_, _ = w.Write(resp)
	}))
	defer tokenServer.Close()

	// Mock Apple JWKS endpoint.
	jwksServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksData)
	}))
	defer jwksServer.Close()

	p := newTestAppleProvider(t, tokenServer.URL, jwksServer.URL)
	p.httpClient = &http.Client{
		Transport: &appleEndpointRewriter{
			tokenURL: tokenServer.URL,
			jwksURL:  jwksServer.URL,
		},
	}

	ctx := WithCodeVerifier(context.Background(), "test-verifier")
	user, err := p.ExchangeCode(ctx, "auth-code")
	require.NoError(t, err)

	assert.Equal(t, "apple-user-001", user.ProviderUserID)
	assert.Equal(t, "user@icloud.com", user.Email)
}

func TestAppleProvider_ExchangeCode_TokenEndpointError(t *testing.T) {
	tokenServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer tokenServer.Close()

	p := newTestAppleProvider(t, tokenServer.URL, "")
	p.httpClient = &http.Client{
		Transport: &appleEndpointRewriter{tokenURL: tokenServer.URL, jwksURL: ""},
	}

	ctx := WithCodeVerifier(context.Background(), "verifier")
	_, err := p.ExchangeCode(ctx, "bad-code")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exchange token")
}

func TestAppleProvider_GenerateClientSecret(t *testing.T) {
	p := newTestAppleProvider(t, "", "")

	secret, err := p.generateClientSecret()
	require.NoError(t, err)
	assert.NotEmpty(t, secret)

	// Parse the JWT without verification to check claims.
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(secret, jwt.MapClaims{})
	require.NoError(t, err)

	claims := token.Claims.(jwt.MapClaims)
	iss, _ := claims.GetIssuer()
	assert.Equal(t, "TEAM123", iss)
	sub, _ := claims.GetSubject()
	assert.Equal(t, "com.example.app", sub)
	aud, _ := claims.GetAudience()
	assert.Contains(t, aud, appleIssuer)
	assert.Equal(t, "KEY456", token.Header["kid"])
	assert.Equal(t, "ES256", token.Header["alg"])
}

func TestJWKToRSAPublicKey(t *testing.T) {
	key := generateTestRSAKey(t)
	pub := &key.PublicKey

	jwk := appleJWK{
		KTY: "RSA",
		KID: "test",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}

	got, err := jwkToRSAPublicKey(jwk)
	require.NoError(t, err)
	assert.Equal(t, pub.N, got.N)
	assert.Equal(t, pub.E, got.E)
}

func TestJWKToRSAPublicKey_InvalidModulus(t *testing.T) {
	jwk := appleJWK{N: "!!invalid!!", E: "AQAB"}
	_, err := jwkToRSAPublicKey(jwk)
	assert.Error(t, err)
}

// appleEndpointRewriter redirects Apple API calls to test servers.
type appleEndpointRewriter struct {
	tokenURL string
	jwksURL  string
}

func (a *appleEndpointRewriter) RoundTrip(req *http.Request) (*http.Response, error) {
	switch {
	case req.URL.String() == appleTokenURL || req.URL.Host == "appleid.apple.com" && req.URL.Path == "/auth/token":
		newReq := req.Clone(req.Context())
		parsed, _ := url.Parse(a.tokenURL)
		newReq.URL = parsed
		newReq.Host = parsed.Host
		return http.DefaultTransport.RoundTrip(newReq)
	case req.URL.String() == appleJWKSURL || req.URL.Host == "appleid.apple.com" && req.URL.Path == "/auth/keys":
		newReq := req.Clone(req.Context())
		parsed, _ := url.Parse(a.jwksURL)
		newReq.URL = parsed
		newReq.Host = parsed.Host
		return http.DefaultTransport.RoundTrip(newReq)
	}
	return http.DefaultTransport.RoundTrip(req)
}
