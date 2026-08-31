package e2e

import (
	"bytes"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
)

// adminAPIKeyWithSecret mirrors api.AdminAPIKeyWithSecret's JSON shape,
// returned only from create and rotate.
type adminAPIKeyWithSecret struct {
	ID              string `json:"id"`
	ClientID        string `json:"client_id"`
	Key             string `json:"key"`
	GracePeriodEnds string `json:"grace_period_ends,omitempty"`
}

// TestAPIKeyLifecycle is a regression guard for GH-485 and exercises the
// API-key lifecycle end to end: create -> validate -> rotate -> old key
// valid in grace, new key valid -> revoke -> both rejected.
//
// GAP (documented here rather than tracked as a separate review-003 item,
// since none references this specifically): there is no public endpoint
// that successfully *consumes* an API key end to end today.
// middleware.APIKeyMiddleware (internal/middleware/apikey.go:56-64) accepts
// X-API-Key on the protected /auth/* routes and sets "claims"/"client_id"/
// "scopes" into the Gin context on a valid key, but never sets "user_id".
// AuthMiddleware skips re-running when "claims" is already set
// (internal/middleware/auth.go:44-48), so "user_id" is never populated
// either. Every handler behind those routes reads identity via
// c.GetString("user_id") (e.g. AuthHandlers.Me, internal/api/auth_handlers.go:104),
// which is empty, so a *validly authenticated* API key always gets
// 401 "missing user identity" from the handler layer — a different error,
// from a different layer, than an *invalid* key gets (401 "invalid or
// expired API key" from the middleware itself, before any handler runs).
//
// That distinction is exactly what this test drives ValidateAPIKey through:
// hitting GET /auth/me with X-API-Key set. "missing user identity" (handler
// layer) proves the key validated successfully; "invalid or expired API
// key" (middleware layer) proves it did not. There is no way to observe an
// actual successful request with today's wiring.
func TestAPIKeyLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	// An API key must belong to a client.
	owner := createAdminServiceClient(t, "E2E APIKey Owner "+uuid.NewString(), nil, nil)

	// 1. Create.
	created := createAdminAPIKey(t, owner.ID, "e2e-key", []string{"read:users"})
	require.True(t, len(created.Key) > len("qf_ak_") && created.Key[:6] == "qf_ak_",
		"api key must have qf_ak_ prefix, got %q", created.Key)
	originalKey := created.Key

	// 2. Validate: a fresh, active key passes ValidateAPIKey (observed as
	// "missing user identity" — see the gap documented above), while
	// garbage does not (observed as "invalid or expired API key").
	requireAPIKeyValidates(t, originalKey)
	requireAPIKeyRejected(t, "qf_ak_0000000000000000000000000000000000")

	// 3. Rotate.
	rotated := rotateAdminAPIKey(t, created.ID)
	require.True(t, len(rotated.Key) > len("qf_ak_") && rotated.Key[:6] == "qf_ak_",
		"rotated api key must have qf_ak_ prefix, got %q", rotated.Key)
	require.NotEqual(t, originalKey, rotated.Key, "rotation must generate a new key")
	require.NotEmpty(t, rotated.GracePeriodEnds, "rotate response must include grace_period_ends")
	newKey := rotated.Key

	// 4. Old key still valid in the grace window (hardcoded 24h,
	// internal/admin/apikey_service.go:28 — same no-config-knob situation as
	// client secrets, so this asserts immediately-after-rotation validity
	// rather than waiting for/simulating expiry).
	requireAPIKeyValidates(t, originalKey)

	// 5. New key valid.
	requireAPIKeyValidates(t, newKey)

	// 6. Revoke.
	revokeReq, err := http.NewRequest(http.MethodDelete, suite.AdminBaseURL+"/admin/apikeys/"+created.ID, http.NoBody)
	require.NoError(t, err)
	revokeResp, err := suite.HTTPClient.Do(revokeReq)
	require.NoError(t, err, "revoke api key request")
	defer func() { _ = revokeResp.Body.Close() }()
	require.Equal(t, http.StatusOK, revokeResp.StatusCode, "revoke api key status")

	// 7. Both old and new keys rejected after revocation.
	requireAPIKeyRejected(t, originalKey)
	requireAPIKeyRejected(t, newKey)
}

// createAdminAPIKey creates an API key for clientID via POST /admin/apikeys.
func createAdminAPIKey(t *testing.T, clientID, name string, scopes []string) adminAPIKeyWithSecret {
	t.Helper()

	body, err := json.Marshal(map[string]interface{}{
		"client_id": clientID,
		"name":      name,
		"scopes":    scopes,
	})
	require.NoError(t, err)

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/apikeys", bytes.NewReader(body))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "create api key request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create api key status")

	var created adminAPIKeyWithSecret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&created))
	require.NotEmpty(t, created.ID)
	return created
}

// rotateAdminAPIKey rotates keyID via POST /admin/apikeys/:id/rotate.
func rotateAdminAPIKey(t *testing.T, keyID string) adminAPIKeyWithSecret {
	t.Helper()

	req, err := http.NewRequest(http.MethodPost, suite.AdminBaseURL+"/admin/apikeys/"+keyID+"/rotate", http.NoBody)
	require.NoError(t, err)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "rotate api key request")
	defer func() { _ = resp.Body.Close() }()
	require.Equal(t, http.StatusOK, resp.StatusCode, "rotate api key status")

	var rotated adminAPIKeyWithSecret
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&rotated))
	return rotated
}

// meWithAPIKey calls GET /auth/me with X-API-Key set to key and returns the
// status and decoded error envelope, driving ValidateAPIKey through the only
// public surface that reaches it (see the gap documented on
// TestAPIKeyLifecycle).
func meWithAPIKey(t *testing.T, key string) (int, errorEnvelope) {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, suite.PublicBaseURL+"/auth/me", http.NoBody)
	require.NoError(t, err)
	req.Header.Set("X-API-Key", key)

	resp, err := suite.HTTPClient.Do(req)
	require.NoError(t, err, "GET /auth/me with X-API-Key")
	defer func() { _ = resp.Body.Close() }()

	var errResp errorEnvelope
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	return resp.StatusCode, errResp
}

// requireAPIKeyValidates asserts key passes ValidateAPIKey (middleware
// layer), surfaced as the handler-layer "missing user identity" 401 per the
// documented gap.
func requireAPIKeyValidates(t *testing.T, key string) {
	t.Helper()
	status, errResp := meWithAPIKey(t, key)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "missing user identity", errResp.Error, "key should have validated (this specific message proves it passed APIKeyMiddleware)")
}

// requireAPIKeyRejected asserts key fails ValidateAPIKey outright (rejected
// by the middleware itself, never reaching the handler).
func requireAPIKeyRejected(t *testing.T, key string) {
	t.Helper()
	status, errResp := meWithAPIKey(t, key)
	require.Equal(t, http.StatusUnauthorized, status)
	require.Equal(t, "invalid or expired API key", errResp.Error)
}
