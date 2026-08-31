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

// registerResponse mirrors api.UserInfo's JSON shape.
type registerResponse struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// authResponse mirrors api.AuthResult's JSON shape (the fields the golden
// path and MFA flow tests care about; omitempty fields not exercised here
// are left zero).
type authResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	UserID       string `json:"user_id"`
	MFARequired  bool   `json:"mfa_required,omitempty"`
	MFAToken     string `json:"mfa_token,omitempty"`
}

// TestGoldenPath_RegisterLoginMeRefreshLogout proves the harness end to
// end: register -> login -> GET /me -> refresh -> logout, over real HTTP
// against the actual service image (not hand-wired mocks). Follow-up
// issues (A2-A4) add further flows in sibling test files using the same
// `suite` Env.
func TestGoldenPath_RegisterLoginMeRefreshLogout(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	email := fmt.Sprintf("e2e-%s@example.com", uuid.NewString())

	// 1. Register.
	registerBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
		"name":     "E2E Golden Path",
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
	require.Equal(t, email, registered.Email)

	// 2. Login.
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
	require.True(t, len(login.AccessToken) > len("qf_at_") && login.AccessToken[:6] == "qf_at_",
		"access token must have qf_at_ prefix, got %q", login.AccessToken)
	require.True(t, len(login.RefreshToken) > len("qf_rt_") && login.RefreshToken[:6] == "qf_rt_",
		"refresh token must have qf_rt_ prefix, got %q", login.RefreshToken)

	// 3. GET /me with the login access token.
	meReq, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/auth/me", http.NoBody)
	require.NoError(t, err)
	meReq.Header.Set("Authorization", "Bearer "+login.AccessToken)

	meResp, err := client.Do(meReq)
	require.NoError(t, err, "me request")
	defer func() { _ = meResp.Body.Close() }()
	require.Equal(t, http.StatusOK, meResp.StatusCode, "me status")

	var me registerResponse
	require.NoError(t, json.NewDecoder(meResp.Body).Decode(&me))
	require.Equal(t, registered.ID, me.ID)
	require.Equal(t, email, me.Email)

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
	require.True(t, len(refreshed.AccessToken) > len("qf_at_") && refreshed.AccessToken[:6] == "qf_at_",
		"refreshed access token must have qf_at_ prefix, got %q", refreshed.AccessToken)
	require.True(t, len(refreshed.RefreshToken) > len("qf_rt_") && refreshed.RefreshToken[:6] == "qf_rt_",
		"refreshed refresh token must have qf_rt_ prefix, got %q", refreshed.RefreshToken)
	require.NotEqual(t, login.AccessToken, refreshed.AccessToken, "refresh must rotate the access token")
	require.NotEqual(t, login.RefreshToken, refreshed.RefreshToken, "refresh must rotate the refresh token")

	// 5. Logout with the refreshed access token.
	logoutReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/logout", http.NoBody)
	require.NoError(t, err)
	logoutReq.Header.Set("Authorization", "Bearer "+refreshed.AccessToken)

	logoutResp, err := client.Do(logoutReq)
	require.NoError(t, err, "logout request")
	defer func() { _ = logoutResp.Body.Close() }()
	require.Equal(t, http.StatusOK, logoutResp.StatusCode, "logout status")

	var logoutBody map[string]string
	require.NoError(t, json.NewDecoder(logoutResp.Body).Decode(&logoutBody))
	require.Equal(t, "Logged out", logoutBody["message"])
}
