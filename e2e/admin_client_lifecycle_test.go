package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// adminClient mirrors api.AdminClient's JSON shape (no secret field).
type adminClient struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	ClientType   string   `json:"client_type"`
	Scopes       []string `json:"scopes"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
}

// adminClientWithSecret mirrors api.AdminClientWithSecret's JSON shape,
// returned only from create and rotate-secret.
type adminClientWithSecret struct {
	adminClient
	ClientSecret    string `json:"client_secret"`
	GracePeriodEnds string `json:"grace_period_ends,omitempty"`
}

// oidcTokenResponse is declared in oidc_flow_test.go (same package), which
// carries the full field set; this file decodes the subset it needs.

// redirectResponse mirrors api.RedirectResponse's JSON shape.
type redirectResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// errorEnvelope mirrors domain.ErrorResponse's JSON shape.
type errorEnvelope struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

// noRedirectClient never follows redirects, so callers can inspect the
// Location header on 302s from GET /oauth/authorize instead of the harness
// trying (and failing) to actually dial the fake login UI URL.
var noRedirectClient = &http.Client{
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// TestAdminClientLifecycle exercises the admin client (service-type)
// lifecycle end to end (GH-499 / issue A4): create -> rotate secret -> old
// secret still exchanges during the 24h grace window -> new secret exchanges
// -> update scopes -> soft-delete -> operations against the deleted client
// fail.
//
// The only place a client secret is actually verified today is
// ProviderService.ExchangeCode (internal/oidc/provider_service.go:200-205),
// reached via POST /oauth/token with grant_type=authorization_code — the
// client_credentials grant is a stub that always 500s (see the
// "client_credentials grant is unimplemented" sub-test below). So proving
// the secret grace window works means driving a full (if minimal)
// authorize -> admin login-accept -> token authorization_code round trip
// for a first-party ("service" type, admin-owned) client, which
// auto-consents and skips the separate consent step entirely
// (internal/oidc/consent_service.go:112, isThirdParty is false for
// admin-owned clients).
func TestAdminClientLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	redirectURI := "http://e2e.invalid/callback"

	// 0. A subject to log in as. The login/consent admin API trusts whatever
	// subject id it's given (it's the harness standing in for a login UI
	// that would normally authenticate the user first), so registration
	// alone (no email verification, no password login) is enough.
	subjectEmail := fmt.Sprintf("e2e-admin-client-%s@example.com", uuid.NewString())
	registerBody, err := json.Marshal(map[string]string{
		"email":    subjectEmail,
		"password": fakeUserPassword,
		"name":     "E2E Admin Client Lifecycle Subject",
	})
	require.NoError(t, err)
	registerReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(registerBody))
	require.NoError(t, err)
	registerReq.Header.Set("Content-Type", "application/json")
	registerResp, err := client.Do(registerReq)
	require.NoError(t, err, "register subject")
	defer func() { _ = registerResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, registerResp.StatusCode, "register subject status")
	var subject registerResponse
	require.NoError(t, json.NewDecoder(registerResp.Body).Decode(&subject))

	// 1. Create a service client with a secret (qf_cs_ prefix).
	created := createAdminServiceClient(t, "E2E Admin Client "+uuid.NewString(), []string{"openid"}, []string{redirectURI})
	require.True(t, len(created.ClientSecret) > len("qf_cs_") && created.ClientSecret[:6] == "qf_cs_",
		"client secret must have qf_cs_ prefix, got %q", created.ClientSecret)
	originalSecret := created.ClientSecret

	// 2. Rotate the secret. The old secret must remain valid until
	// GracePeriodEnds (hardcoded 24h server-side, internal/admin/client_service.go:27
	// — there is no config knob to shorten it for tests). We don't need to
	// fast-forward a clock to prove the *grace* path works: we assert
	// immediately after rotation, which is trivially within the 24h window
	// with no wait or injected clock needed. What we do NOT test is
	// expiry *after* the grace window, since that would require either a
	// real 24h wait or a clock injection point that doesn't exist in this
	// codebase today.
	rotated := rotateAdminClientSecret(t, created.ID)
	require.True(t, len(rotated.ClientSecret) > len("qf_cs_") && rotated.ClientSecret[:6] == "qf_cs_",
		"rotated client secret must have qf_cs_ prefix, got %q", rotated.ClientSecret)
	require.NotEqual(t, originalSecret, rotated.ClientSecret, "rotation must generate a new secret")
	require.NotEmpty(t, rotated.GracePeriodEnds, "rotate response must include grace_period_ends")
	newSecret := rotated.ClientSecret

	// 3. The OLD secret must still exchange a fresh authorization code
	// during the grace window.
	oldSecretTokens := exchangeAuthCodeForClient(t, created.ID, redirectURI, subject.ID, "openid", originalSecret)
	require.NotEmpty(t, oldSecretTokens.AccessToken, "old secret should still exchange during grace period")

	// 4. The NEW secret must also work.
	newSecretTokens := exchangeAuthCodeForClient(t, created.ID, redirectURI, subject.ID, "openid", newSecret)
	require.NotEmpty(t, newSecretTokens.AccessToken, "new secret must exchange")

	// 5. A wrong secret must be rejected.
	authCode := issueAuthCode(t, created.ID, redirectURI, subject.ID, "openid")
	wrongSecretStatus, wrongSecretErr := attemptCodeExchange(t, authCode, redirectURI, created.ID, "qf_cs_0000000000000000000000000000000000000000000000000000000000000000")
	require.Equal(t, http.StatusUnauthorized, wrongSecretStatus, "wrong secret must be rejected")
	require.Equal(t, "UNAUTHORIZED", wrongSecretErr.Code)

	// 6. Update scopes.
	updateBody, err := json.Marshal(map[string]interface{}{"scopes": []string{"openid", "profile"}})
	require.NoError(t, err)
	updateReq, err := http.NewRequest(http.MethodPatch, suite.AdminBaseURL+"/admin/clients/"+created.ID, bytes.NewReader(updateBody))
	require.NoError(t, err)
	updateReq.Header.Set("Content-Type", "application/json")
	updateResp, err := client.Do(updateReq)
	require.NoError(t, err, "update client scopes")
	defer func() { _ = updateResp.Body.Close() }()
	require.Equal(t, http.StatusOK, updateResp.StatusCode, "update client scopes status")
	var updated adminClient
	require.NoError(t, json.NewDecoder(updateResp.Body).Decode(&updated))
	require.ElementsMatch(t, []string{"openid", "profile"}, updated.Scopes)

	// 7. Soft-delete.
	deleteReq, err := http.NewRequest(http.MethodDelete, suite.AdminBaseURL+"/admin/clients/"+created.ID, http.NoBody)
	require.NoError(t, err)
	deleteResp, err := client.Do(deleteReq)
	require.NoError(t, err, "delete client")
	defer func() { _ = deleteResp.Body.Close() }()
	require.Equal(t, http.StatusOK, deleteResp.StatusCode, "delete client status")

	// 8. Operations against the deleted client fail: update -> 404 (the
	// repository filters out revoked clients), rotate-secret -> 404,
	// delete again -> 409 (already deleted). See
	// internal/storage/client_repository.go and
	// internal/api/auth_handlers.go:196-209 (handleServiceError) for the
	// exact status mapping.
	updateAfterDeleteReq, err := http.NewRequest(http.MethodPatch, suite.AdminBaseURL+"/admin/clients/"+created.ID, bytes.NewReader(updateBody))
	require.NoError(t, err)
	updateAfterDeleteReq.Header.Set("Content-Type", "application/json")
	updateAfterDeleteResp, err := client.Do(updateAfterDeleteReq)
	require.NoError(t, err, "update deleted client")
	defer func() { _ = updateAfterDeleteResp.Body.Close() }()
	require.Equal(t, http.StatusNotFound, updateAfterDeleteResp.StatusCode, "update on deleted client must 404")

	rotateAfterDeleteReq, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/clients/"+created.ID+"/rotate-secret", http.NoBody)
	require.NoError(t, err)
	rotateAfterDeleteResp, err := client.Do(rotateAfterDeleteReq)
	require.NoError(t, err, "rotate secret on deleted client")
	defer func() { _ = rotateAfterDeleteResp.Body.Close() }()
	require.Equal(t, http.StatusNotFound, rotateAfterDeleteResp.StatusCode, "rotate-secret on deleted client must 404")

	deleteAgainReq, err := http.NewRequest(http.MethodDelete, suite.AdminBaseURL+"/admin/clients/"+created.ID, http.NoBody)
	require.NoError(t, err)
	deleteAgainResp, err := client.Do(deleteAgainReq)
	require.NoError(t, err, "delete deleted client again")
	defer func() { _ = deleteAgainResp.Body.Close() }()
	require.Equal(t, http.StatusConflict, deleteAgainResp.StatusCode, "deleting an already-deleted client must 409")
}

// TestAdminClientCredentialsGrantIsUnimplemented documents a real gap found
// while implementing GH-499: POST /auth/token with grant_type=client_credentials
// is wired end to end (routed, validated) but token.Service.ClientCredentials
// (internal/token/service.go:271-276) is a stub that unconditionally returns
// an error, so the endpoint always 500s. This is not the client-auth path
// exercised by TestAdminClientLifecycle (that goes through
// POST /oauth/token's authorization_code grant, the only grant that
// currently verifies a client secret) — it's called out separately so a
// future implementation of client_credentials flips this assertion rather
// than silently going unnoticed.
func TestAdminClientCredentialsGrantIsUnimplemented(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	created := createAdminServiceClient(t, "E2E ClientCreds Stub "+uuid.NewString(), nil, nil)

	body, err := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     created.ID,
		"client_secret": created.ClientSecret,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/token", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "client_credentials request")
	defer func() { _ = resp.Body.Close() }()

	require.Equal(t, http.StatusInternalServerError, resp.StatusCode,
		"client_credentials grant is an unimplemented stub (internal/token/service.go:271-276); "+
			"if this starts passing, update this test rather than deleting it")
}

// createAdminServiceClient creates a "service"-type OAuth2 client via
// POST /admin/clients and returns the decoded response (including the
// one-time-visible secret).
func createAdminServiceClient(t *testing.T, name string, scopes, redirectURIs []string) adminClientWithSecret {
	t.Helper()

	if scopes == nil {
		scopes = []string{}
	}
	if redirectURIs == nil {
		redirectURIs = []string{}
	}

	body, err := json.Marshal(map[string]interface{}{
		"name":          name,
		"client_type":   "service",
		"scopes":        scopes,
		"redirect_uris": redirectURIs,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/clients", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "create client request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create client status")

	var created adminClientWithSecret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.NotEmpty(t, created.ID)
	return created
}

// rotateAdminClientSecret rotates clientID's secret via
// POST /admin/clients/:id/rotate-secret and returns the decoded response.
func rotateAdminClientSecret(t *testing.T, clientID string) adminClientWithSecret {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/clients/"+clientID+"/rotate-secret", http.NoBody)
	require.NoError(t, err)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "rotate secret request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "rotate secret status")

	var rotated adminClientWithSecret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rotated))
	return rotated
}

// issueAuthCode drives GET /oauth/authorize -> PUT
// /admin/oauth/auth/requests/login?accept=true for an admin-owned
// ("first-party") client, which auto-consents and issues a fresh, single-use
// authorization code without a separate consent step. Returns the code.
func issueAuthCode(t *testing.T, clientID, redirectURI, subjectID, scope string) string {
	t.Helper()

	authorizeURL := fmt.Sprintf("%s/oauth/authorize?%s", suite.PublicBaseURL, url.Values{
		"client_id":     {clientID},
		"redirect_uri":  {redirectURI},
		"response_type": {"code"},
		"scope":         {scope},
		"state":         {"e2e-state-" + uuid.NewString()},
	}.Encode())

	authorizeReq, err := http.NewRequest(http.MethodGet, authorizeURL, http.NoBody)
	require.NoError(t, err)

	authorizeResp, err := noRedirectClient.Do(authorizeReq)
	require.NoError(t, err, "authorize request")
	defer func() { _ = authorizeResp.Body.Close() }()
	require.Equal(t, http.StatusFound, authorizeResp.StatusCode, "authorize status")

	loginRedirect, err := url.Parse(authorizeResp.Header.Get("Location"))
	require.NoError(t, err, "parse authorize redirect")
	loginChallenge := loginRedirect.Query().Get("login_challenge")
	require.NotEmpty(t, loginChallenge, "authorize redirect must carry login_challenge")

	acceptBody, err := json.Marshal(map[string]string{"subject": subjectID})
	require.NoError(t, err)

	acceptReq, err := http.NewRequest(http.MethodPut,
		suite.AdminBaseURL+"/admin/oauth/auth/requests/login?login_challenge="+loginChallenge+"&accept=true",
		bytes.NewReader(acceptBody))
	require.NoError(t, err)
	acceptReq.Header.Set("Content-Type", "application/json")

	acceptResp, err := suite.HTTPClient.Do(acceptReq)
	require.NoError(t, err, "accept login request")
	defer func() { _ = acceptResp.Body.Close() }()
	require.Equal(t, http.StatusOK, acceptResp.StatusCode, "accept login status")

	var accepted redirectResponse
	require.NoError(t, json.NewDecoder(acceptResp.Body).Decode(&accepted))

	codeRedirect, err := url.Parse(accepted.RedirectTo)
	require.NoError(t, err, "parse accept-login redirect")
	code := codeRedirect.Query().Get("code")
	require.NotEmpty(t, code, "accept-login redirect must carry an authorization code (client is admin-owned, so consent is skipped)")

	return code
}

// exchangeAuthCodeForClient issues a fresh authorization code for clientID
// and exchanges it for tokens using secret, requiring success.
func exchangeAuthCodeForClient(t *testing.T, clientID, redirectURI, subjectID, scope, secret string) oidcTokenResponse {
	t.Helper()

	code := issueAuthCode(t, clientID, redirectURI, subjectID, scope)

	status, tokenResp, errResp := codeExchange(t, code, redirectURI, clientID, secret)
	require.Equal(t, http.StatusOK, status, "code exchange status (error: %+v)", errResp)
	return tokenResp
}

// attemptCodeExchange exchanges an existing authorization code with secret
// and returns the status and decoded error body, for negative-path
// assertions (the caller supplies a code expected to fail, e.g. a
// deliberately wrong secret).
func attemptCodeExchange(t *testing.T, code, redirectURI, clientID, secret string) (int, errorEnvelope) {
	t.Helper()
	status, _, errResp := codeExchange(t, code, redirectURI, clientID, secret)
	return status, errResp
}

// codeExchange POSTs /oauth/token with grant_type=authorization_code and
// decodes either the success or error body depending on status.
func codeExchange(t *testing.T, code, redirectURI, clientID, secret string) (int, oidcTokenResponse, errorEnvelope) {
	t.Helper()

	body, err := json.Marshal(map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  redirectURI,
		"client_id":     clientID,
		"client_secret": secret,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/oauth/token", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "token exchange request")
	defer func() { _ = resp.Body.Close() }()

	var tokenResp oidcTokenResponse
	var errResp errorEnvelope
	raw, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.Unmarshal(raw, &tokenResp))
	} else {
		require.NoError(t, json.Unmarshal(raw, &errResp))
	}

	return resp.StatusCode, tokenResp, errResp
}
