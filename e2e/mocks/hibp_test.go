package mocks

import (
	"context"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHIBPMock_Miss(t *testing.T) {
	m := NewHIBPMock()
	defer m.Close()

	resp := getRange(t, m.URL(), "5BAA6")
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Empty(t, body)
	assert.Equal(t, []string{"5BAA6"}, m.Requests())
}

func TestHIBPMock_PasswordBreached(t *testing.T) {
	m := NewHIBPMock()
	defer m.Close()

	// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
	m.MarkPasswordBreached("password", 3730471)

	resp := getRange(t, m.URL(), "5BAA6")
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "1E4C9B93F3F0682250B6CF8331B7EE68FD8:3730471")
}

func TestHIBPMock_BreachedSuffixOnlyAffectsItsPrefix(t *testing.T) {
	m := NewHIBPMock()
	defer m.Close()
	m.MarkBreachedSuffix("ABCDE", "SUFFIX1", 5)

	hitResp := getRange(t, m.URL(), "ABCDE")
	defer func() { _ = hitResp.Body.Close() }()
	hitBody, err := io.ReadAll(hitResp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(hitBody), "SUFFIX1:5")

	missResp := getRange(t, m.URL(), "00000")
	defer func() { _ = missResp.Body.Close() }()
	missBody, err := io.ReadAll(missResp.Body)
	require.NoError(t, err)
	assert.Empty(t, missBody)
}

func TestHIBPMock_Port(t *testing.T) {
	m := NewHIBPMock()
	defer m.Close()

	port, err := m.Port()
	require.NoError(t, err)
	assert.NotZero(t, port)
}

func getRange(t *testing.T, baseURL, prefix string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, baseURL+"/range/"+prefix, http.NoBody)
	require.NoError(t, err)
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	return resp
}
