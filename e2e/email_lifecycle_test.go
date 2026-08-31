package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// waitForTokenTimeout bounds how long a test polls EmailSinkMock for a
// verify/reset link before failing; generous relative to the harness's own
// readiness/HTTP timeouts since delivery is local (no real network hop).
const waitForTokenTimeout = 10 * time.Second

// introspectResponse mirrors api.IntrospectionResponse's JSON shape (RFC 7662).
type introspectResponse struct {
	Active bool   `json:"active"`
	Sub    string `json:"sub,omitempty"`
}

// TestGoldenPath_RegisterVerifyLoginRefreshIntrospectLogout extends the A1
// harness flow (GH-493) with the email-dependent leg: register -> pull the
// verification link out of EmailSinkMock -> verify-email -> login -> refresh
// -> admin introspect the refresh token (active:true, correct sub) -> logout
// with the refresh token in the body -> introspect again (active:false).
// This is the email-flow analog of GH-486 (logout must revoke the
// refresh token DB row, not just the access token).
func TestGoldenPath_RegisterVerifyLoginRefreshIntrospectLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	email := fmt.Sprintf("e2e-verify-%s@example.com", uuid.NewString())

	// 1. Register.
	registerBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
		"name":     "E2E Email Lifecycle",
	})
	require.NoError(t, err)

	registerReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(registerBody))
	require.NoError(t, err)
	registerReq.Header.Set("Content-Type", "application/json")

	registerResp, err := client.Do(registerReq)
	require.NoError(t, err, "register request")
	defer func() { _ = registerResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, registerResp.StatusCode, "register status")

	var registered registerResponse
	require.NoError(t, json.NewDecoder(registerResp.Body).Decode(&registered))
	require.NotEmpty(t, registered.ID, "registered user id")

	// 2. Pull the verification link out of the email sink (poll, no sleep)
	// and verify the email.
	ctx, cancel := context.WithTimeout(context.Background(), waitForTokenTimeout)
	defer cancel()

	verifyToken, err := suite.EmailSink.WaitForToken(ctx, email, fakeEmailVerifyURLBase, waitForTokenTimeout)
	require.NoError(t, err, "waiting for verification email")
	require.NotEmpty(t, verifyToken)

	verifyBody, err := json.Marshal(map[string]string{"token": verifyToken})
	require.NoError(t, err)

	verifyReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/verify-email", bytes.NewReader(verifyBody))
	require.NoError(t, err)
	verifyReq.Header.Set("Content-Type", "application/json")

	verifyResp, err := client.Do(verifyReq)
	require.NoError(t, err, "verify-email request")
	defer func() { _ = verifyResp.Body.Close() }()
	require.Equal(t, http.StatusOK, verifyResp.StatusCode, "verify-email status")

	// 3. Login.
	loginBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
	})
	require.NoError(t, err)

	loginReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/login", bytes.NewReader(loginBody))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/json")

	loginResp, err := client.Do(loginReq)
	require.NoError(t, err, "login request")
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login status")

	var login authResponse
	require.NoError(t, json.NewDecoder(loginResp.Body).Decode(&login))
	require.Equal(t, registered.ID, login.UserID)

	// 4. Refresh.
	refreshBody, err := json.Marshal(map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": login.RefreshToken,
	})
	require.NoError(t, err)

	refreshReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/token", bytes.NewReader(refreshBody))
	require.NoError(t, err)
	refreshReq.Header.Set("Content-Type", "application/json")

	refreshResp, err := client.Do(refreshReq)
	require.NoError(t, err, "refresh request")
	defer func() { _ = refreshResp.Body.Close() }()
	require.Equal(t, http.StatusOK, refreshResp.StatusCode, "refresh status")

	var refreshed authResponse
	require.NoError(t, json.NewDecoder(refreshResp.Body).Decode(&refreshed))
	require.NotEmpty(t, refreshed.RefreshToken)

	// 5. Admin introspect the (rotated) refresh token: active, correct sub.
	introspectActive := introspectToken(t, client, refreshed.RefreshToken)
	require.True(t, introspectActive.Active, "refresh token should be active before logout")
	require.Equal(t, registered.ID, introspectActive.Sub)

	// 6. Logout, sending the refresh token in the body so its DB row is
	// revoked too (GH-486), not just the access token via the blocklist.
	logoutBody, err := json.Marshal(map[string]string{"refresh_token": refreshed.RefreshToken})
	require.NoError(t, err)

	logoutReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/logout", bytes.NewReader(logoutBody))
	require.NoError(t, err)
	logoutReq.Header.Set("Content-Type", "application/json")
	logoutReq.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)

	logoutResp, err := client.Do(logoutReq)
	require.NoError(t, err, "logout request")
	defer func() { _ = logoutResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode, "logout status")

	// 7. Introspect again: the refresh token must now be inactive.
	introspectAfter := introspectToken(t, client, refreshed.RefreshToken)
	require.False(t, introspectAfter.Active, "refresh token should be inactive after logout")
}

// introspectToken calls POST /admin/tokens/introspect for token and decodes
// the RFC 7662 response.
func introspectToken(t *testing.T, client *http.Client, token string) introspectResponse {
	t.Helper()

	body, err := json.Marshal(map[string]string{"token": token})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/tokens/introspect", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err, "introspect request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "introspect status")

	var result introspectResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}
