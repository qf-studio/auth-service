package hibp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
// prefix = 5BAA6, suffix = 1E4C9B93F3F0682250B6CF8331B7EE68FD8

func TestIsBreached_FoundInResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/range/5BAA6", r.URL.Path)
		assert.Equal(t, "qf-studio-auth-service", r.Header.Get("User-Agent"))
		_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:2\r\n1E4C9B93F3F0682250B6CF8331B7EE68FD8:10000000\r\n003D68EB55068C33ACE09247EE4C639306B:3\r\n"))
	}))
	defer srv.Close()

	c := &Client{httpClient: srv.Client(), apiURL: srv.URL + "/range/"}
	breached, err := c.IsBreached(context.Background(), "password")
	require.NoError(t, err)
	assert.True(t, breached)
}

func TestIsBreached_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("0018A45C4D1DEF81644B54AB7F969B88D65:2\r\n003D68EB55068C33ACE09247EE4C639306B:3\r\n"))
	}))
	defer srv.Close()

	c := &Client{httpClient: srv.Client(), apiURL: srv.URL + "/range/"}
	breached, err := c.IsBreached(context.Background(), "password")
	require.NoError(t, err)
	assert.False(t, breached)
}

func TestIsBreached_APIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	c := &Client{httpClient: srv.Client(), apiURL: srv.URL + "/range/"}
	_, err := c.IsBreached(context.Background(), "password")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unexpected status 503")
}

func TestMatchesSuffix(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		suffix  string
		want    bool
	}{
		{
			name:   "match",
			body:   "ABC:1\r\nDEF:2\r\n",
			suffix: "DEF",
			want:   true,
		},
		{
			name:   "no match",
			body:   "ABC:1\r\nDEF:2\r\n",
			suffix: "GHI",
			want:   false,
		},
		{
			name:   "case insensitive",
			body:   "abc:1\r\n",
			suffix: "ABC",
			want:   true,
		},
		{
			name:   "empty body",
			body:   "",
			suffix: "ABC",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchesSuffix(strings.NewReader(tt.body), tt.suffix)
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
