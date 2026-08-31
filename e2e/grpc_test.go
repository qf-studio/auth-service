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

	"github.com/qf-studio/auth-service/pkg/authclient"
)

// grpcCallTimeout bounds individual authclient RPCs in these tests.
const grpcCallTimeout = 10 * time.Second

// dialAuthClient dials suite.GRPCAddr (the SUT's gRPC port, published as
// 4002/tcp — see e2e/harness.go's sutGRPCPort and the docker-compose
// GRPC_PORT mapping added in 2333a60) with WithInsecure, since the harness
// runs the SUT without TLS. Every call through the returned client that
// reaches the server (rather than failing at dial) is itself the regression
// guard for that port-publishing gap: if 4002 stopped being exposed/wired,
// dialing would still "succeed" (gRPC dials lazily) but every RPC below
// would fail with Unavailable.
func dialAuthClient(t *testing.T) *authclient.Client {
	t.Helper()

	c, err := authclient.New(suite.GRPCAddr, authclient.WithInsecure())
	require.NoError(t, err, "dial authclient at %s", suite.GRPCAddr)
	t.Cleanup(func() { _ = c.Close() })
	return c
}

// registerAndLoginUser registers a fresh user via the public HTTP API and
// logs in, returning the registered user id and the login's access token
// (qf_at_-prefixed).
func registerAndLoginUser(t *testing.T, label string) (userID, accessToken string) {
	t.Helper()

	client := suite.HTTPClient
	email := fmt.Sprintf("e2e-grpc-%s-%s@example.com", label, uuid.NewString())

	registerBody, err := json.Marshal(map[string]string{
		"email":    email,
		"password": fakeUserPassword,
		"name":     "E2E gRPC " + label,
	})
	require.NoError(t, err)
	registerReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(registerBody))
	require.NoError(t, err)
	registerReq.Header.Set("Content-Type", "application/json")
	registerResp, err := client.Do(registerReq)
	require.NoError(t, err, "register")
	defer func() { _ = registerResp.Body.Close() }()
	require.Equal(t, http.StatusCreated, registerResp.StatusCode, "register status")
	var registered registerResponse
	require.NoError(t, json.NewDecoder(registerResp.Body).Decode(&registered))

	loginBody, err := json.Marshal(map[string]string{"email": email, "password": fakeUserPassword})
	require.NoError(t, err)
	loginReq, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/login", bytes.NewReader(loginBody))
	require.NoError(t, err)
	loginReq.Header.Set("Content-Type", "application/json")
	loginResp, err := client.Do(loginReq)
	require.NoError(t, err, "login")
	defer func() { _ = loginResp.Body.Close() }()
	require.Equal(t, http.StatusOK, loginResp.StatusCode, "login status")
	var login authResponse
	require.NoError(t, json.NewDecoder(loginResp.Body).Decode(&login))

	return registered.ID, login.AccessToken
}

// revokeAccessToken blocklists accessToken via POST /auth/logout (no body,
// so only the access token's jti is revoked — matches the golden-path
// logout convention in golden_path_test.go).
func revokeAccessToken(t *testing.T, accessToken string) {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/logout", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "logout request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "logout status")
}

// TestGRPC_ValidateToken exercises AuthServiceServer.ValidateToken via
// pkg/authclient: a valid token resolves claims, garbage is rejected, and a
// revoked token is still reported Valid — the latter is a known gap
// (ValidateToken never calls token.Service.IsRevoked, unlike
// IntrospectToken; contrast internal/grpc/auth_service.go:49-67 with
// :110-141) captured here as a pinned regression rather than a surprise.
func TestGRPC_ValidateToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	authc := dialAuthClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), grpcCallTimeout)
	defer cancel()

	userID, accessToken := registerAndLoginUser(t, "validate")

	result, err := authc.ValidateToken(ctx, accessToken)
	require.NoError(t, err, "ValidateToken on a valid token")
	require.True(t, result.Valid)
	require.NotNil(t, result.Claims)
	require.Equal(t, userID, result.Claims.Subject)

	_, err = authc.ValidateToken(ctx, "not-a-real-token-"+uuid.NewString())
	require.Error(t, err, "ValidateToken on garbage (no qf_at_ prefix) must error, not just report Valid:false")

	revokeAccessToken(t, accessToken)

	// GAP: revocation is not checked by ValidateToken (only by
	// IntrospectToken, see TestGRPC_IntrospectToken below). This assertion
	// pins that known behavior rather than testing for the ideal one.
	afterRevoke, err := authc.ValidateToken(ctx, accessToken)
	require.NoError(t, err)
	require.True(t, afterRevoke.Valid, "documented gap: ValidateToken does not check the revocation blocklist")
}

// TestGRPC_IntrospectToken exercises AuthServiceServer.IntrospectToken,
// which (unlike ValidateToken) does check revocation.
func TestGRPC_IntrospectToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	authc := dialAuthClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), grpcCallTimeout)
	defer cancel()

	userID, accessToken := registerAndLoginUser(t, "introspect")

	active, err := authc.IntrospectToken(ctx, accessToken)
	require.NoError(t, err)
	require.True(t, active.Active)
	require.NotNil(t, active.Claims)
	require.Equal(t, userID, active.Claims.Subject)

	revokeAccessToken(t, accessToken)

	afterRevoke, err := authc.IntrospectToken(ctx, accessToken)
	require.NoError(t, err)
	require.False(t, afterRevoke.Active, "IntrospectToken must report revoked tokens as inactive")
}

// TestGRPC_GetUser exercises AuthServiceServer.GetUser.
func TestGRPC_GetUser(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	authc := dialAuthClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), grpcCallTimeout)
	defer cancel()

	userID, _ := registerAndLoginUser(t, "getuser")

	user, err := authc.GetUser(ctx, userID)
	require.NoError(t, err)
	require.Equal(t, userID, user.ID)
	require.False(t, user.Locked)

	_, err = authc.GetUser(ctx, uuid.NewString())
	require.Error(t, err, "GetUser on a nonexistent user id must error")
}
