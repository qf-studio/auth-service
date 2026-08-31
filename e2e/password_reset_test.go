package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// TestGoldenPath_PasswordReset exercises request -> EmailSinkMock link ->
// confirm, then proves the old password is rejected and the new one is
// accepted: register -> request password reset -> pull the reset link out
// of EmailSinkMock -> confirm with a new password -> login with the old
// password fails (401) -> login with the new password succeeds (200).
func TestGoldenPath_PasswordReset(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	email := fmt.Sprintf("e2e-reset-%s@example.com", uuid.NewString())
	const newPassword = "a brand new e2e password 2026" //nolint:gosec // fake, test-only

	// 1. Register.
	registerBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
		"name":     "E2E Password Reset",
	})
	require.NoError(t, err)

	registerReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(registerBody))
	require.NoError(t, err)
	registerReq.Header.Set("Content-Type", "application/json")

	registerResp, err := client.Do(registerReq)
	require.NoError(t, err, "register request")
	defer func() { _ = registerResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, registerResp.StatusCode, "register status")

	// 2. Request a password reset.
	resetReqBody, err := json.Marshal(map[string]string{"email": email})
	require.NoError(t, err)

	resetReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/password/reset", bytes.NewReader(resetReqBody))
	require.NoError(t, err)
	resetReq.Header.Set("Content-Type", "application/json")

	resetResp, err := client.Do(resetReq)
	require.NoError(t, err, "password reset request")
	defer func() { _ = resetResp.Body.Close() }()
	require.Equal(t, http.StatusAccepted, resetResp.StatusCode, "password reset status")

	// 3. Pull the reset link out of the email sink (poll, no sleep).
	ctx, cancel := context.WithTimeout(context.Background(), waitForTokenTimeout)
	defer cancel()

	resetToken, err := suite.EmailSink.WaitForToken(ctx, email, waitForTokenTimeout)
	require.NoError(t, err, "waiting for password reset email")
	require.NotEmpty(t, resetToken)

	// 4. Confirm the reset with a new password.
	confirmBody, err := json.Marshal(map[string]string{
		"token":        resetToken,
		"new_password": newPassword,
	})
	require.NoError(t, err)

	confirmReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/password/reset/confirm", bytes.NewReader(confirmBody))
	require.NoError(t, err)
	confirmReq.Header.Set("Content-Type", "application/json")

	confirmResp, err := client.Do(confirmReq)
	require.NoError(t, err, "password reset confirm request")
	defer func() { _ = confirmResp.Body.Close() }()
	require.Equal(t, http.StatusOK, confirmResp.StatusCode, "password reset confirm status")

	// 5. Old password must now be rejected.
	oldLoginBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
	})
	require.NoError(t, err)

	oldLoginReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/login", bytes.NewReader(oldLoginBody))
	require.NoError(t, err)
	oldLoginReq.Header.Set("Content-Type", "application/json")

	oldLoginResp, err := client.Do(oldLoginReq)
	require.NoError(t, err, "login with old password request")
	defer func() { _ = oldLoginResp.Body.Close() }()
	require.Equal(t, http.StatusUnauthorized, oldLoginResp.StatusCode, "login with old password must be rejected")

	// 6. New password must be accepted.
	newLoginBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": newPassword,
	})
	require.NoError(t, err)

	newLoginReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/login", bytes.NewReader(newLoginBody))
	require.NoError(t, err)
	newLoginReq.Header.Set("Content-Type", "application/json")

	newLoginResp, err := client.Do(newLoginReq)
	require.NoError(t, err, "login with new password request")
	defer func() { _ = newLoginResp.Body.Close() }()
	require.Equal(t, http.StatusOK, newLoginResp.StatusCode, "login with new password must succeed")

	var login authResponse
	require.NoError(t, json.NewDecoder(newLoginResp.Body).Decode(&login))
	require.NotEmpty(t, login.AccessToken)
}
