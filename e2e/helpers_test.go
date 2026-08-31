package e2e

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// newE2EEmail returns a fresh, unique email address for a throwaway e2e
// test user.
func newE2EEmail(label string) string {
	return fmt.Sprintf("e2e-%s-%s@example.com", label, uuid.NewString())
}

// postJSON POSTs body (JSON-marshaled, may be nil) to url and decodes the
// response body into out (if non-nil), returning the response status code
// and header. The response body is fully read and closed before returning.
func postJSON(t *testing.T, client *http.Client, url string, body, out any) (int, http.Header) {
	t.Helper()

	reader := bytes.NewReader(nil)
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(http.MethodPost, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	require.NoError(t, err, "POST %s", url)
	defer func() { _ = resp.Body.Close() }()

	if out != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out), "decode response from %s", url)
	}
	return resp.StatusCode, resp.Header
}

// doAuthedJSON performs an HTTP request with a Bearer token, optionally
// JSON-marshaling body (may be nil for no body), and decodes the response
// into out (if non-nil). It returns the response status code and header.
func doAuthedJSON(t *testing.T, client *http.Client, method, url, bearerToken string, body, out any) (int, http.Header) {
	t.Helper()

	reader := bytes.NewReader(nil)
	if body != nil {
		raw, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(raw)
	}

	req, err := http.NewRequest(method, url, reader)
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bearerToken)

	resp, err := client.Do(req)
	require.NoError(t, err, "%s %s", method, url)
	defer func() { _ = resp.Body.Close() }()

	if out != nil {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(out), "decode response from %s %s", method, url)
	}
	return resp.StatusCode, resp.Header
}

// registerUser registers a new user via POST /auth/register and returns the
// decoded response, requiring a 201 status.
func registerUser(t *testing.T, client *http.Client, email, password string) registerResponse {
	t.Helper()

	var registered registerResponse
	status, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/register", map[string]string{
		"email":    email,
		"password": password,
		"name":     "E2E Test User",
	}, &registered)
	require.Equal(t, http.StatusCreated, status, "register status")
	require.NotEmpty(t, registered.ID, "registered user id")
	return registered
}

// loginUser logs in via POST /auth/login and returns the decoded response,
// requiring a 200 status. The response may carry either tokens or an MFA
// challenge (MFARequired/MFAToken), depending on whether the user has MFA
// enabled.
func loginUser(t *testing.T, client *http.Client, email, password string) authResponse {
	t.Helper()

	var login authResponse
	status, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/login", map[string]string{
		"email":    email,
		"password": password,
	}, &login)
	require.Equal(t, http.StatusOK, status, "login status")
	return login
}
