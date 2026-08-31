package e2e

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/pkg/authclient"
)

// This file holds the live-safe subset of the e2e suite (GH-495): every
// exported test here is named with a "TestSmoke" prefix so the
// auth-service-smoke image (docker/Dockerfile.smoke) can select exactly
// this subset with `-test.run=TestSmoke`, and nothing here touches the
// admin port destructively or assumes testcontainers. They run against
// whatever suite points at — the shared testcontainers stack in normal CI
// (`go test ./e2e/...`), or a live deployment when SMOKE_BASE_URL drives
// TestMain into liveEnv (see main_test.go).
//
// Every test still guards itself with testing.Short(), matching every
// other file in this package, so `go test -short ./...` (no Docker, no
// network) never touches suite.

// TestSmoke_HealthAndReadiness proves the public port is up and reports
// itself ready (dependencies reachable) — the cheapest possible signal that
// a deployment is alive, and the first thing worth checking before any
// other smoke leg runs.
func TestSmoke_HealthAndReadiness(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker or SMOKE_BASE_URL)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	for _, path := range []string{"/health", "/readiness"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, suite.PublicBaseURL+path, http.NoBody)
		require.NoError(t, err)

		resp, err := suite.HTTPClient.Do(req)
		require.NoError(t, err, "GET %s", path)
		defer func() { _ = resp.Body.Close() }()
		require.Equal(t, http.StatusOK, resp.StatusCode, "%s status", path)
	}
}

// TestSmoke_DiscoveryAndJWKS proves the OIDC discovery document and JWKS
// endpoint are both served and shaped as expected: a live deployment
// serving a broken/empty JWKS would silently fail every consumer that
// verifies tokens (e.g. Pointer), so this is checked explicitly rather than
// relying on the golden-path login below to catch it indirectly.
func TestSmoke_DiscoveryAndJWKS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker or SMOKE_BASE_URL)")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, suite.PublicBaseURL+"/.well-known/openid-configuration", http.NoBody)
	require.NoError(t, err)
	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "discovery request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "discovery status")

	var discovery oidcDiscoveryResponse
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&discovery))
	require.NotEmpty(t, discovery.Issuer, "discovery issuer")
	require.NotEmpty(t, discovery.JwksURI, "discovery jwks_uri")

	keys, err := fetchJWKS(ctx, suite.HTTPClient, suite.PublicBaseURL)
	require.NoError(t, err, "fetch jwks")
	require.NotEmpty(t, keys, "jwks must publish at least one key")
	require.Equal(t, "EC", keys[0].Kty, "jwks key type")
	require.Equal(t, "P-256", keys[0].Crv, "jwks key curve")
}

// TestSmoke_GoldenPath exercises register -> login -> refresh -> logout
// against the live public API with a throwaway, uniquely-emailed user, plus
// an introspect leg when SMOKE_ADMIN_URL is reachable. It creates only
// disposable identities (a fresh uuid-suffixed email every run) and never
// deletes anything, so running it twice in a row is safe (idempotent).
func TestSmoke_GoldenPath(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker or SMOKE_BASE_URL)")
	}

	client := suite.HTTPClient
	email := newE2EEmail("smoke")

	registered := registerUser(t, client, email, fakeUserPassword)
	require.Equal(t, email, registered.Email)

	login := loginUser(t, client, email, fakeUserPassword)
	require.Equal(t, registered.ID, login.UserID)
	require.True(t, len(login.AccessToken) > len("qf_at_") && login.AccessToken[:6] == "qf_at_",
		"access token must have qf_at_ prefix, got %q", login.AccessToken)
	require.True(t, len(login.RefreshToken) > len("qf_rt_") && login.RefreshToken[:6] == "qf_rt_",
		"refresh token must have qf_rt_ prefix, got %q", login.RefreshToken)

	var refreshed authResponse
	status, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/token", map[string]string{
		"grant_type":    "refresh_token",
		"refresh_token": login.RefreshToken,
	}, &refreshed)
	require.Equal(t, http.StatusOK, status, "refresh status")
	require.True(t, len(refreshed.AccessToken) > len("qf_at_") && refreshed.AccessToken[:6] == "qf_at_",
		"refreshed access token must have qf_at_ prefix, got %q", refreshed.AccessToken)
	require.NotEqual(t, login.AccessToken, refreshed.AccessToken, "refresh must rotate the access token")

	if suite.AdminBaseURL == "" {
		t.Log("SMOKE_ADMIN_URL unset — skipping introspect leg")
	} else {
		var introspected struct {
			Active bool   `json:"active"`
			Sub    string `json:"sub"`
		}
		status, _ := postJSON(t, client, suite.AdminBaseURL+"/admin/tokens/introspect", map[string]string{
			"token": refreshed.AccessToken,
		}, &introspected)
		require.Equal(t, http.StatusOK, status, "introspect status")
		require.True(t, introspected.Active, "introspect must report the fresh access token active")
		require.Equal(t, registered.ID, introspected.Sub, "introspect sub must match the registered user id")
	}

	logoutStatus, _ := doAuthedJSON(t, client, http.MethodPost, suite.PublicBaseURL+"/auth/logout", refreshed.AccessToken, nil, nil)
	require.Equal(t, http.StatusOK, logoutStatus, "logout status")
}

// TestSmoke_GRPCValidateToken exercises AuthServiceServer.ValidateToken via
// pkg/authclient — the same SDK real gRPC consumers use — against a live
// deployment's 4002/tcp port. It skips when SMOKE_GRPC_ADDR is unset, since
// not every deployment target exposes gRPC to the smoke runner.
func TestSmoke_GRPCValidateToken(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker or SMOKE_BASE_URL)")
	}
	if suite.GRPCAddr == "" {
		t.Skip("SMOKE_GRPC_ADDR unset — skipping gRPC smoke leg")
	}

	authc, err := authclient.New(suite.GRPCAddr, authclient.WithInsecure())
	require.NoError(t, err, "dial authclient at %s", suite.GRPCAddr)
	t.Cleanup(func() { _ = authc.Close() })

	email := newE2EEmail("smoke-grpc")
	registered := registerUser(t, suite.HTTPClient, email, fakeUserPassword)
	login := loginUser(t, suite.HTTPClient, email, fakeUserPassword)

	ctx, cancel := context.WithTimeout(context.Background(), grpcCallTimeout)
	defer cancel()

	result, err := authc.ValidateToken(ctx, login.AccessToken)
	require.NoError(t, err, "ValidateToken on a fresh login token")
	require.True(t, result.Valid)
	require.NotNil(t, result.Claims)
	require.Equal(t, registered.ID, result.Claims.Subject)

	_, err = authc.ValidateToken(ctx, fmt.Sprintf("not-a-real-token-%s", email))
	require.Error(t, err, "ValidateToken on garbage must error, not just report Valid:false")
}
