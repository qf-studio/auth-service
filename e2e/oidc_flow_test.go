package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/oauth"
)

// adminClientResponse mirrors api.AdminClientWithSecret's JSON shape (the
// fields this test needs).
type adminClientResponse struct {
	ID           string   `json:"id"`
	ClientType   string   `json:"client_type"`
	RedirectURIs []string `json:"redirect_uris"`
	ClientSecret string   `json:"client_secret"`
}

// oidcDiscoveryResponse mirrors api.OIDCDiscoveryResponse's JSON shape.
type oidcDiscoveryResponse struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
	JwksURI               string `json:"jwks_uri"`
}

// redirectResponse is declared in admin_client_lifecycle_test.go (same
// package); the OIDC flow reuses it for login/consent accept responses.

// oidcTokenResponse mirrors api.OIDCTokenResponse's JSON shape.
type oidcTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// oidcUserInfoResponse mirrors api.OIDCUserInfoResponse's JSON shape.
type oidcUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// idTokenClaims mirrors the subset of internal/token.idTokenClaims this test
// verifies.
type idTokenClaims struct {
	jwt.RegisteredClaims
	Nonce string `json:"nonce,omitempty"`
}

// noRedirectClient (the package-level var in admin_client_lifecycle_test.go)
// is reused here: /oauth/authorize redirects to OIDC_LOGIN_UI_URL (a fake,
// unreachable address in this harness), so callers must inspect the 302's
// Location header instead of following it.

// TestOIDCFlow_AuthorizeLoginTokenUserinfo exercises the full OIDC
// authorization code flow over real HTTP against the SUT image: create a
// client via the admin API, check discovery, drive /oauth/authorize with
// PKCE S256, act as the external login UI via the admin login-accept API
// (this client is first-party, so login-accept issues the code directly
// without a separate consent step), exchange the code, validate the ID
// token, call /userinfo, and prove the authorization code is single-use.
func TestOIDCFlow_AuthorizeLoginTokenUserinfo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	redirectClient := noRedirectClient

	email := newE2EEmail("oidc")
	registered := registerUser(t, client, email, fakeUserPassword)

	redirectURI := "http://e2e-oidc-client.invalid/callback"

	// 1. Create an OAuth2 client via the admin API.
	var adminClient adminClientResponse
	status, _ := postJSON(t, client, suite.AdminBaseURL+"/admin/clients", map[string]any{
		"name":          "E2E OIDC Client " + uuid.NewString(),
		"client_type":   "public",
		"scopes":        []string{"openid", "profile", "email"},
		"redirect_uris": []string{redirectURI},
	}, &adminClient)
	require.Equal(t, http.StatusCreated, status, "create client status")
	require.NotEmpty(t, adminClient.ID)

	// 2. Discovery: endpoints must match the SUT's own public base URL.
	var discovery oidcDiscoveryResponse
	discoveryReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/.well-known/openid-configuration", http.NoBody)
	require.NoError(t, err)
	discoveryResp, err := client.Do(discoveryReq)
	require.NoError(t, err, "discovery request")
	defer func() { _ = discoveryResp.Body.Close() }()
	require.Equal(t, http.StatusOK, discoveryResp.StatusCode, "discovery status")
	require.NoError(t, json.NewDecoder(discoveryResp.Body).Decode(&discovery))

	require.Equal(t, suite.PublicBaseURL, discovery.Issuer, "issuer must match the SUT's public base URL")
	require.Equal(t, suite.PublicBaseURL+"/oauth/authorize", discovery.AuthorizationEndpoint)
	require.Equal(t, suite.PublicBaseURL+"/oauth/token", discovery.TokenEndpoint)
	require.Equal(t, suite.PublicBaseURL+"/userinfo", discovery.UserinfoEndpoint)
	require.Equal(t, suite.PublicBaseURL+"/.well-known/jwks.json", discovery.JwksURI)

	// 3. Authorize with PKCE S256. The SUT responds with a 302 to
	// OIDC_LOGIN_UI_URL carrying a login_challenge; capture it without
	// following (the login UI URL is a fake, unreachable placeholder).
	verifier := oauth.GenerateVerifier()
	challenge := oauth.S256Challenge(verifier)
	state := "state-" + uuid.NewString()
	nonce := "nonce-" + uuid.NewString()

	authorizeQuery := url.Values{
		"client_id":             {adminClient.ID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid profile email"},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}
	authorizeReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/oauth/authorize?"+authorizeQuery.Encode(), http.NoBody)
	require.NoError(t, err)

	authorizeResp, err := redirectClient.Do(authorizeReq)
	require.NoError(t, err, "authorize request")
	defer func() { _ = authorizeResp.Body.Close() }()
	require.Equal(t, http.StatusFound, authorizeResp.StatusCode, "authorize status")

	loginRedirect, err := url.Parse(authorizeResp.Header.Get("Location"))
	require.NoError(t, err, "parse authorize redirect Location")
	loginChallenge := loginRedirect.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge, "authorize redirect must carry a login_challenge")

	// 4. Act as the external login UI: accept the login request via the
	// admin API. This client was created via POST /admin/clients (Owner:
	// "admin", first-party), so AcceptLogin issues the authorization code
	// directly rather than redirecting to a separate consent step.
	var loginAccept redirectResponse
	status, _ = putJSON(t, client, fmt.Sprintf("%s/admin/oauth/auth/requests/login?login_challenge=%s&accept=true",
		suite.AdminBaseURL, url.QueryEscape(loginChallenge)),
		map[string]string{"subject": registered.ID}, &loginAccept)
	require.Equal(t, http.StatusOK, status, "accept login status")

	codeRedirect, err := url.Parse(loginAccept.RedirectTo)
	require.NoError(t, err, "parse login-accept redirect_to")
	require.Equal(t, state, codeRedirect.Query().Get("state"), "code redirect must echo state")
	code := codeRedirect.Query().Get("code")
	require.NotEmpty(t, code, "login accept must issue an authorization code")

	// 5. Exchange the code (public client: no client secret, PKCE verifier
	// instead).
	exchangeBody := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     adminClient.ID,
		"code_verifier": verifier,
	}
	var tokens oidcTokenResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/oauth/token", exchangeBody, &tokens)
	require.Equal(t, http.StatusOK, status, "token exchange status")
	require.NotEmpty(t, tokens.AccessToken, "token exchange must return an access token")
	require.NotEmpty(t, tokens.IDToken, "openid scope was granted, ID token expected")
	require.Empty(t, tokens.RefreshToken, "offline_access was not granted, refresh token must be omitted (GH-541)")

	// 6. Validate the ID token against the live JWKS endpoint: aud, nonce,
	// iss.
	keyfunc, err := fetchJWKSKeyfunc(context.Background(), client, suite.PublicBaseURL)
	require.NoError(t, err, "build JWKS keyfunc")

	var idClaims idTokenClaims
	parsedIDToken, err := jwt.ParseWithClaims(tokens.IDToken, &idClaims, keyfunc, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err, "parse+verify ID token against live JWKS")
	require.True(t, parsedIDToken.Valid)
	require.Equal(t, suite.PublicBaseURL, idClaims.Issuer, "ID token iss must match discovery issuer")
	require.Contains(t, idClaims.Audience, adminClient.ID, "ID token aud must contain the client_id")
	require.Equal(t, nonce, idClaims.Nonce, "ID token nonce must round-trip from the authorize request")
	require.Equal(t, registered.ID, idClaims.Subject)

	// 7. UserInfo with the access token.
	userInfoReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/userinfo", http.NoBody)
	require.NoError(t, err)
	userInfoReq.Header.Set("Authorization", "Bearer "+tokens.AccessToken)

	userInfoResp, err := client.Do(userInfoReq)
	require.NoError(t, err, "userinfo request")
	defer func() { _ = userInfoResp.Body.Close() }()
	require.Equal(t, http.StatusOK, userInfoResp.StatusCode, "userinfo status")

	var userInfo oidcUserInfoResponse
	require.NoError(t, json.NewDecoder(userInfoResp.Body).Decode(&userInfo))
	require.Equal(t, registered.ID, userInfo.Sub)
	require.Equal(t, email, userInfo.Email)

	// 8. Negative: the authorization code is single-use; a second exchange
	// must fail, and (GH-542) it revokes the tokens the first exchange issued.
	require.Equal(t, http.StatusOK, meStatus(t, client, tokens.AccessToken), "access token works before the code is reused")

	status, _ = postJSON(t, client, suite.PublicBaseURL+"/oauth/token", exchangeBody, nil)
	require.NotEqual(t, http.StatusOK, status, "reused authorization code must be rejected")

	require.Equal(t, http.StatusUnauthorized, meStatus(t, client, tokens.AccessToken),
		"access token issued from a reused code must be revoked")
}

// meStatus returns the status of GET /auth/me with accessToken as bearer.
func meStatus(t *testing.T, client *http.Client, accessToken string) int {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/auth/me", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	resp, err := client.Do(req)
	require.NoError(t, err, "me request")
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// putJSON is postJSON's PUT sibling: used for the admin login/consent
// accept endpoints, which are PUT requests.
func putJSON(t *testing.T, client *http.Client, target string, body, out any) (int, http.Header) {
	t.Helper()

	raw, err := json.Marshal(body)
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPut, target, bytes.NewReader(raw))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err, "PUT %s", target)
	defer func() { _ = resp.Body.Close() }()

	if out != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out), "decode response from PUT %s", target)
	}
	return resp.StatusCode, resp.Header
}

// TestOIDCFlow_OfflineAccessIssuesRefreshToken covers GH-541: when the client
// has offline_access in its scopes and the authorize request asks for it, the
// code exchange returns a refresh token that the refresh grant accepts.
func TestOIDCFlow_OfflineAccessIssuesRefreshToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient

	registered := registerUser(t, client, newE2EEmail("oidc-offline"), fakeUserPassword)
	redirectURI := "http://e2e-oidc-offline.invalid/callback"

	var adminClient adminClientResponse
	status, _ := postJSON(t, client, suite.AdminBaseURL+"/admin/clients", map[string]any{
		"name":          "E2E OIDC Offline Client " + uuid.NewString(),
		"client_type":   "public",
		"scopes":        []string{"openid", "offline_access"},
		"redirect_uris": []string{redirectURI},
	}, &adminClient)
	require.Equal(t, http.StatusCreated, status, "create client status")

	verifier := oauth.GenerateVerifier()
	state := "state-" + uuid.NewString()
	authorizeQuery := url.Values{
		"client_id":             {adminClient.ID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid offline_access"},
		"state":                 {state},
		"nonce":                 {"nonce-" + uuid.NewString()},
		"code_challenge":        {oauth.S256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authorizeReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/oauth/authorize?"+authorizeQuery.Encode(), http.NoBody)
	require.NoError(t, err)
	authorizeResp, err := noRedirectClient.Do(authorizeReq)
	require.NoError(t, err, "authorize request")
	defer func() { _ = authorizeResp.Body.Close() }()
	require.Equal(t, http.StatusFound, authorizeResp.StatusCode, "authorize status")

	loginRedirect, err := url.Parse(authorizeResp.Header.Get("Location"))
	require.NoError(t, err)
	loginChallenge := loginRedirect.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge)

	var loginAccept redirectResponse
	status, _ = putJSON(t, client, fmt.Sprintf("%s/admin/oauth/auth/requests/login?login_challenge=%s&accept=true",
		suite.AdminBaseURL, url.QueryEscape(loginChallenge)),
		map[string]string{"subject": registered.ID}, &loginAccept)
	require.Equal(t, http.StatusOK, status, "accept login status")

	codeRedirect, err := url.Parse(loginAccept.RedirectTo)
	require.NoError(t, err)
	code := codeRedirect.Query().Get("code")
	require.NotEmpty(t, code)

	var tokens oidcTokenResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/oauth/token", map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     adminClient.ID,
		"code_verifier": verifier,
	}, &tokens)
	require.Equal(t, http.StatusOK, status, "token exchange status")
	require.NotEmpty(t, tokens.AccessToken)
	require.NotEmpty(t, tokens.RefreshToken, "offline_access was granted, refresh token expected")

	var refreshed authResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": tokens.RefreshToken,
	}, &refreshed)
	require.Equal(t, http.StatusOK, status, "refresh grant status")
	require.NotEmpty(t, refreshed.AccessToken)
	require.NotEmpty(t, refreshed.RefreshToken)
}

// TestOIDCFlow_CodeReuseRevokesRefreshFamily covers GH-542: redeeming a code
// twice revokes the refresh token issued by the first redemption, including
// its rotated successors, while the user's own login session keeps working.
func TestOIDCFlow_CodeReuseRevokesRefreshFamily(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient

	email := newE2EEmail("oidc-reuse")
	registered := registerUser(t, client, email, fakeUserPassword)
	var session authResponse
	status, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/login", map[string]string{
		"email": email, "password": fakeUserPassword,
	}, &session)
	require.Equal(t, http.StatusOK, status, "login status")

	redirectURI := "http://e2e-oidc-reuse.invalid/callback"
	var adminClient adminClientResponse
	status, _ = postJSON(t, client, suite.AdminBaseURL+"/admin/clients", map[string]any{
		"name":          "E2E OIDC Reuse Client " + uuid.NewString(),
		"client_type":   "public",
		"scopes":        []string{"openid", "offline_access"},
		"redirect_uris": []string{redirectURI},
	}, &adminClient)
	require.Equal(t, http.StatusCreated, status, "create client status")

	verifier := oauth.GenerateVerifier()
	authorizeQuery := url.Values{
		"client_id":             {adminClient.ID},
		"redirect_uri":          {redirectURI},
		"response_type":         {"code"},
		"scope":                 {"openid offline_access"},
		"state":                 {"state-" + uuid.NewString()},
		"code_challenge":        {oauth.S256Challenge(verifier)},
		"code_challenge_method": {"S256"},
	}
	authorizeReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/oauth/authorize?"+authorizeQuery.Encode(), http.NoBody)
	require.NoError(t, err)
	authorizeResp, err := noRedirectClient.Do(authorizeReq)
	require.NoError(t, err, "authorize request")
	defer func() { _ = authorizeResp.Body.Close() }()
	require.Equal(t, http.StatusFound, authorizeResp.StatusCode, "authorize status")
	loginRedirect, err := url.Parse(authorizeResp.Header.Get("Location"))
	require.NoError(t, err)

	var loginAccept redirectResponse
	status, _ = putJSON(t, client, fmt.Sprintf("%s/admin/oauth/auth/requests/login?login_challenge=%s&accept=true",
		suite.AdminBaseURL, url.QueryEscape(loginRedirect.Query().Get("login_challenge"))),
		map[string]string{"subject": registered.ID}, &loginAccept)
	require.Equal(t, http.StatusOK, status, "accept login status")
	codeRedirect, err := url.Parse(loginAccept.RedirectTo)
	require.NoError(t, err)
	code := codeRedirect.Query().Get("code")
	require.NotEmpty(t, code)

	exchangeBody := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     adminClient.ID,
		"code_verifier": verifier,
	}
	var tokens oidcTokenResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/oauth/token", exchangeBody, &tokens)
	require.Equal(t, http.StatusOK, status, "token exchange status")
	require.NotEmpty(t, tokens.RefreshToken)

	// Rotate once so the original refresh key is gone: only the family can
	// reach the live successor.
	var rotated authResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": tokens.RefreshToken,
	}, &rotated)
	require.Equal(t, http.StatusOK, status, "refresh grant status")
	require.NotEmpty(t, rotated.RefreshToken)

	status, _ = postJSON(t, client, suite.PublicBaseURL+"/oauth/token", exchangeBody, nil)
	require.NotEqual(t, http.StatusOK, status, "reused authorization code must be rejected")

	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": rotated.RefreshToken,
	}, nil)
	require.Equal(t, http.StatusUnauthorized, status, "rotated successor of the reused code's refresh token must be revoked")
	require.Equal(t, http.StatusUnauthorized, meStatus(t, client, tokens.AccessToken))

	require.Equal(t, http.StatusOK, meStatus(t, client, session.AccessToken), "the user's own login session is unaffected")
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/token", map[string]string{
		"grant_type": "refresh_token", "refresh_token": session.RefreshToken,
	}, nil)
	require.Equal(t, http.StatusOK, status, "the user's own refresh token is unaffected")
}
