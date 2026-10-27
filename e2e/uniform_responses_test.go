package e2e

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestUniformResponses_NoAccountStateDisclosure covers GH-528 end to end: a
// duplicate registration looks like a new one, and login failures for an
// unknown email and for a wrong password are indistinguishable.
func TestUniformResponses_NoAccountStateDisclosure(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping e2e test in short mode (requires Docker)")
	}

	client := suite.HTTPClient
	addr := fmt.Sprintf("e2e-uniform-%s@example.com", uuid.NewString())
	registerBody := map[string]string{"email": addr, "password": fakeUserPassword, "name": "E2E Uniform"}

	var first, second map[string]any
	status, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/register", registerBody, &first)
	require.Equal(t, http.StatusCreated, status)

	status, _ = postJSON(t, client, suite.PublicBaseURL+"/auth/register", registerBody, &second)
	require.Equal(t, http.StatusCreated, status, "duplicate registration must look like a new one")
	assert.Equal(t, addr, second["email"])
	assert.NotEqual(t, first["id"], second["id"], "the duplicate response carries a placeholder id, not the real account")
	for k := range first {
		assert.Contains(t, second, k)
	}
	assert.Len(t, second, len(first))

	var wrongPassword, unknownEmail map[string]any
	wrongStatus, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/login",
		map[string]string{"email": addr, "password": "not-the-right-password-1"}, &wrongPassword)
	unknownStatus, _ := postJSON(t, client, suite.PublicBaseURL+"/auth/login",
		map[string]string{"email": fmt.Sprintf("nobody-%s@example.com", uuid.NewString()), "password": "not-the-right-password-1"}, &unknownEmail)

	require.Equal(t, http.StatusUnauthorized, wrongStatus)
	require.Equal(t, wrongStatus, unknownStatus)
	assert.Equal(t, "invalid credentials", wrongPassword["error"])
	assert.Equal(t, wrongPassword, unknownEmail)
}
