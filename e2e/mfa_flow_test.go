package e2e

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"github.com/stretchr/testify/require"
)

// mfaEnrollmentResponse mirrors api.MFAEnrollmentResult's JSON shape.
type mfaEnrollmentResponse struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// mfaConfirmResponse mirrors api.MFAConfirmResult's JSON shape.
type mfaConfirmResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

// accessTokenClaims mirrors the subset of internal/token.customClaims this
// test cares about: the roles claim GH-488 regressed on.
type accessTokenClaims struct {
	jwt.RegisteredClaims
	Roles []string `json:"roles,omitempty"`
}

// TestMFAFlow_SetupConfirmChallengeVerifyBackupCode exercises the full MFA
// lifecycle over real HTTP against the SUT image: register+login, enroll,
// confirm with a computed TOTP code, prove a fresh login now returns an MFA
// challenge instead of tokens, complete the challenge, verify the resulting
// access token's roles claim against the live JWKS endpoint (GH-488
// regression guard), then verify a backup-code login once.
func TestMFAFlow_SetupConfirmChallengeVerifyBackupCode(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	email := newE2EEmail("mfa")

	registered := registerUser(t, client, email, fakeUserPassword)

	// 1. Login before MFA is enabled: plain tokens, no challenge.
	preMFALogin := loginUser(t, client, email, fakeUserPassword)
	require.False(t, preMFALogin.MFARequired)
	require.NotEmpty(t, preMFALogin.AccessToken)

	// 2. Setup: initiate TOTP enrollment.
	var enrollment mfaEnrollmentResponse
	status, _ := doAuthedJSON(t, client, http.MethodPost, suite.PublicBaseURL+"/auth/mfa/setup", preMFALogin.AccessToken, nil, &enrollment)
	require.Equal(t, http.StatusOK, status, "mfa setup status")
	require.NotEmpty(t, enrollment.Secret, "mfa enrollment secret")

	// 3. Confirm: compute the current TOTP code from the enrolled secret and
	// confirm enrollment, capturing backup codes for step 7.
	confirmCode, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err, "generate confirm TOTP code")

	var confirm mfaConfirmResponse
	status, _ = doAuthedJSON(t, client, http.MethodPost, suite.PublicBaseURL+"/auth/mfa/confirm", preMFALogin.AccessToken,
		map[string]string{"code": confirmCode}, &confirm)
	require.Equal(t, http.StatusOK, status, "mfa confirm status")
	require.NotEmpty(t, confirm.BackupCodes, "mfa confirm must return backup codes")

	// 4. Fresh login now returns an MFA challenge, not tokens.
	challenge := loginUser(t, client, email, fakeUserPassword)
	require.True(t, challenge.MFARequired, "login after MFA enrollment must require MFA")
	require.NotEmpty(t, challenge.MFAToken, "login must return an mfa_token")
	require.Empty(t, challenge.AccessToken, "no access token should be issued before the MFA challenge is completed")

	// 5. Complete the challenge with a freshly computed TOTP code.
	verifyCode, err := totp.GenerateCode(enrollment.Secret, time.Now())
	require.NoError(t, err, "generate verify TOTP code")

	var verified authResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/mfa/verify", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      verifyCode,
	}, &verified)
	require.Equal(t, http.StatusOK, status, "mfa verify status")
	require.NotEmpty(t, verified.AccessToken, "mfa verify must return an access token")
	require.True(t, len(verified.AccessToken) > len("qf_at_") && verified.AccessToken[:6] == "qf_at_",
		"access token must have qf_at_ prefix, got %q", verified.AccessToken)

	// 6. Fetch the live JWKS and verify the access token's roles claim
	// (GH-488 regression guard): parse+verify against the real endpoint, not
	// a locally shared key.
	keyfunc, err := fetchJWKSKeyfunc(context.Background(), client, suite.PublicBaseURL)
	require.NoError(t, err, "build JWKS keyfunc")

	rawAccessJWT := trimTokenPrefix(verified.AccessToken, "qf_at_")
	var claims accessTokenClaims
	parsed, err := jwt.ParseWithClaims(rawAccessJWT, &claims, keyfunc, jwt.WithValidMethods([]string{"ES256"}))
	require.NoError(t, err, "parse+verify access token against live JWKS")
	require.True(t, parsed.Valid)
	require.Equal(t, registered.ID, claims.Subject)
	require.Contains(t, claims.Roles, "user", "access token roles claim must include the default 'user' role")

	// 7. Backup-code login: a fresh login again requires MFA (still
	// enabled); complete it with one of the backup codes instead of TOTP.
	backupChallenge := loginUser(t, client, email, fakeUserPassword)
	require.True(t, backupChallenge.MFARequired)
	require.NotEmpty(t, backupChallenge.MFAToken)

	var backupResult authResponse
	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/mfa/verify", map[string]string{
		"mfa_token": backupChallenge.MFAToken,
		"code":      confirm.BackupCodes[0],
		"code_type": "backup",
	}, &backupResult)
	require.Equal(t, http.StatusOK, status, "mfa verify (backup code) status")
	require.NotEmpty(t, backupResult.AccessToken, "backup code login must return an access token")
}

// trimTokenPrefix strips a known token prefix (e.g. "qf_at_") so the
// remainder can be parsed as a compact JWT.
func trimTokenPrefix(token, prefix string) string {
	if len(token) > len(prefix) && token[:len(prefix)] == prefix {
		return token[len(prefix):]
	}
	return token
}
