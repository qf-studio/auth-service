package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// This file encodes the review-003 wave-2 backlog (DEVELOPMENT-README
// Current Focus) as real, already-wired acceptance tests that are skipped
// today because the behavior they check for doesn't exist yet. Each fix PR
// should unskip its test as the acceptance check for that fix — the
// skip-reason convention below ("review-003: <topic> — unskip when fixed")
// is what makes `grep t.Skip` on this package double as the backlog.

// TestWave2_ClientCreateRejectsUnknownScope (review-003 wave-2) would prove
// POST /admin/clients rejects a client_type=service create carrying an
// unrecognized scope. It is skipped because nothing validates scope values
// on the live path: internal/api/admin_services.go's CreateClientRequest
// tags Scopes `validate:"omitempty"` only (no oneof/custom check), even
// though internal/domain/admin.go defines a ValidScopes allowlist and a
// "valid_scope" validator tag — that validator is wired to a *different*,
// dead CreateClientRequest type in internal/domain/admin.go, never to the
// one admin_client_handlers.go actually binds and validates.
func TestWave2_ClientCreateRejectsUnknownScope(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	t.Skip("review-003: arbitrary scopes accepted on client create (CreateClientRequest.Scopes has no value validation) — unskip when fixed")

	body, err := json.Marshal(map[string]interface{}{
		"name":          "E2E Wave2 Bad Scope " + uuid.NewString(),
		"client_type":   "service",
		"scopes":        []string{"not-a-real-scope"},
		"redirect_uris": []string{},
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/clients", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "create client request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "create client with bogus scope must be rejected")
}

// TestWave2_UnknownTenantIDIsRejected (review-003 wave-2) would prove a
// request carrying X-Tenant-ID for a tenant that doesn't exist is rejected
// rather than silently proceeding as if no tenant header had been sent. It
// is skipped because tenant resolution is entirely unwired: main.go builds
// middleware.TenantMiddleware nowhere and never sets
// api.MiddlewareStack.Tenant, so router.go's "if mw.Tenant != nil" guard is
// always false and the middleware never runs on any request — an unknown
// (or any) X-Tenant-ID header is a complete no-op today.
func TestWave2_UnknownTenantIDIsRejected(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	t.Skip("review-003: X-Tenant-ID resolution unwired (middleware.TenantMiddleware never added to MiddlewareStack in main.go) — unskip when fixed")

	body, err := json.Marshal(map[string]string{
		"email":    newE2EEmail("wave2-tenant"),
		"password": fakeUserPassword,
		"name":     "E2E Wave2 Unknown Tenant",
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Tenant-ID", uuid.NewString()) // a syntactically valid but nonexistent tenant ID

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "register request")
	defer func() { _ = resp.Body.Close() }()
	require.NotEqual(t, http.StatusCreated, resp.StatusCode,
		"request with an unknown X-Tenant-ID must be rejected, not silently defaulted")
}

// TestWave2_UserRoleTokenRejectedOnAdminRoute (review-003 wave-2) would
// prove a regular user's access token can't be used to call an
// admin-scoped route. It is skipped because the admin router has no
// authorization at all today: NewAdminRouter's own doc comment says "Only
// correlation ID middleware is applied (no auth, no rate limiting). The
// admin port is protected at the network level" — and
// middleware.RequireRoles/RequireScopes/RequireClientType
// (internal/middleware/rbac.go) are never referenced by router.go or
// admin_router.go, so RBAC middleware is applied to no route at all, admin
// or public.
func TestWave2_UserRoleTokenRejectedOnAdminRoute(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	t.Skip("review-003: RBAC middleware applied to no route (admin router has no auth check at all) — unskip when fixed")

	email := newE2EEmail("wave2-rbac")
	registerUser(t, suite.HTTPClient, email, fakeUserPassword)
	login := loginUser(t, suite.HTTPClient, email, fakeUserPassword)
	require.NotEmpty(t, login.AccessToken)

	status, _ := doAuthedJSON(t, suite.HTTPClient, http.MethodGet, suite.AdminBaseURL+"/admin/users", login.AccessToken, nil, nil)
	require.True(t, status == http.StatusUnauthorized || status == http.StatusForbidden,
		"a plain user-role access token must not be accepted on an admin route, got status %d", status)
}

// TestWave2_RegisterRejectsBreachedPassword (review-003 wave-2) would prove
// registering with a password HIBPMock reports as breached is rejected. It
// is skipped because internal/auth.Service never calls its
// hibp.BreachChecker: the field (internal/auth/service.go:64) is wired in
// but grep for "breaches." in that file turns up nothing outside the
// struct/constructor — Register never consults it.
func TestWave2_RegisterRejectsBreachedPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}
	t.Skip("review-003: HIBP never called (internal/auth.Service.breaches is wired but Register never invokes it) — unskip when fixed")

	breachedPassword := "e2e-known-breached-password-wave2" //nolint:gosec // fake, test-only
	suite.HIBP.MarkPasswordBreached(breachedPassword, 42)

	body, err := json.Marshal(map[string]string{
		"email":    newE2EEmail("wave2-hibp"),
		"password": breachedPassword,
		"name":     "E2E Wave2 Breached Password",
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.PublicBaseURL+"/auth/register", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "register request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "register with a known-breached password must be rejected")
}
