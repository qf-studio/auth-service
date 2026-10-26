package middleware_test

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/middleware"
)

// albCIDRs mirrors the production TRUSTED_PROXY_CIDRS (the ALB subnets).
var albCIDRs = []string{"10.40.0.0/24", "10.40.1.0/24"}

func parseCIDRs(t *testing.T, cidrs ...string) []*net.IPNet {
	t.Helper()
	out := make([]*net.IPNet, 0, len(cidrs))
	for _, s := range cidrs {
		_, n, err := net.ParseCIDR(s)
		require.NoError(t, err)
		out = append(out, n)
	}
	return out
}

func newClientIPRouter(t *testing.T, cidrs []*net.IPNet) *gin.Engine {
	t.Helper()
	r := gin.New()
	require.NoError(t, middleware.ConfigureClientIP(r, cidrs))
	r.GET("/ip", func(c *gin.Context) {
		c.String(http.StatusOK, c.ClientIP())
	})
	return r
}

func TestConfigureClientIP(t *testing.T) {
	tests := []struct {
		name       string
		cidrs      []string
		remoteAddr string
		headers    map[string]string
		want       string
	}{
		{
			name:       "no CIDRs configured: forwarded header from any peer is ignored",
			cidrs:      nil,
			remoteAddr: "10.40.0.5:4321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "10.40.0.5",
		},
		{
			name:       "untrusted peer: forwarded header is ignored",
			cidrs:      albCIDRs,
			remoteAddr: "198.51.100.7:4321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "198.51.100.7",
		},
		{
			name:       "trusted peer: rightmost untrusted entry wins over client-supplied leftmost",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.0.5:4321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9, 1.2.3.4"},
			want:       "1.2.3.4",
		},
		{
			name:       "trusted peer: trusted hops on the right are skipped",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.1.20:4321",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.9, 1.2.3.4, 10.40.0.9"},
			want:       "1.2.3.4",
		},
		{
			name:       "trusted peer: single forwarded entry is the client",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.0.5:4321",
			headers:    map[string]string{"X-Forwarded-For": "1.2.3.4"},
			want:       "1.2.3.4",
		},
		{
			name:       "trusted peer without forwarded header: peer address",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.0.5:4321",
			want:       "10.40.0.5",
		},
		{
			name:       "trusted peer: X-Real-IP is not consulted",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.0.5:4321",
			headers:    map[string]string{"X-Real-IP": "9.9.9.9"},
			want:       "10.40.0.5",
		},
		{
			name:       "trusted peer: unparseable forwarded header falls back to peer",
			cidrs:      albCIDRs,
			remoteAddr: "10.40.0.5:4321",
			headers:    map[string]string{"X-Forwarded-For": "not-an-ip"},
			want:       "10.40.0.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			router := newClientIPRouter(t, parseCIDRs(t, tt.cidrs...))

			w := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/ip", http.NoBody)
			req.RemoteAddr = tt.remoteAddr
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			router.ServeHTTP(w, req)

			require.Equal(t, http.StatusOK, w.Code)
			assert.Equal(t, tt.want, w.Body.String())
		})
	}
}

func TestConfigureClientIP_NilCIDRIsError(t *testing.T) {
	err := middleware.ConfigureClientIP(gin.New(), []*net.IPNet{nil})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trusted proxies")
}

// TestRateLimit_BucketKeyedOnDerivedClientIP checks that the per-IP limiter,
// on an engine configured via ConfigureClientIP, keys on the derived client
// address: varying the client-supplied part of X-Forwarded-For never yields
// a fresh bucket.
func TestRateLimit_BucketKeyedOnDerivedClientIP(t *testing.T) {
	type call struct {
		remoteAddr string
		xff        string
		wantCode   int
	}
	tests := []struct {
		name  string
		cidrs []string
		calls []call
	}{
		{
			name:  "untrusted peer, rotating forwarded header: one bucket",
			cidrs: albCIDRs,
			calls: []call{
				{remoteAddr: "198.51.100.7:1111", xff: "1.1.1.1", wantCode: http.StatusOK},
				{remoteAddr: "198.51.100.7:2222", xff: "2.2.2.2", wantCode: http.StatusTooManyRequests},
			},
		},
		{
			name:  "no CIDRs configured, rotating forwarded header: one bucket",
			cidrs: nil,
			calls: []call{
				{remoteAddr: "10.40.0.5:1111", xff: "1.1.1.1", wantCode: http.StatusOK},
				{remoteAddr: "10.40.0.5:2222", xff: "2.2.2.2", wantCode: http.StatusTooManyRequests},
			},
		},
		{
			name:  "trusted peer, same real client, rotating leftmost entry: one bucket",
			cidrs: albCIDRs,
			calls: []call{
				{remoteAddr: "10.40.0.5:1111", xff: "1.1.1.1, 5.5.5.5", wantCode: http.StatusOK},
				{remoteAddr: "10.40.1.6:2222", xff: "2.2.2.2, 5.5.5.5", wantCode: http.StatusTooManyRequests},
			},
		},
		{
			name:  "trusted peer, distinct real clients: separate buckets",
			cidrs: albCIDRs,
			calls: []call{
				{remoteAddr: "10.40.0.5:1111", xff: "1.1.1.1, 5.5.5.5", wantCode: http.StatusOK},
				{remoteAddr: "10.40.0.5:2222", xff: "1.1.1.1, 6.6.6.6", wantCode: http.StatusOK},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Burst 1 refilling once per second: an immediate second request
			// in the same bucket is rejected.
			rl := middleware.NewRateLimiter(config.RateLimitConfig{RPS: 1, Burst: 1})
			router := gin.New()
			require.NoError(t, middleware.ConfigureClientIP(router, parseCIDRs(t, tt.cidrs...)))
			router.Use(rl.Handler())
			router.GET("/test", func(c *gin.Context) {
				c.String(http.StatusOK, "ok")
			})

			for i, cl := range tt.calls {
				w := httptest.NewRecorder()
				req := httptest.NewRequest(http.MethodGet, "/test", http.NoBody)
				req.RemoteAddr = cl.remoteAddr
				req.Header.Set("X-Forwarded-For", cl.xff)
				router.ServeHTTP(w, req)
				assert.Equal(t, cl.wantCode, w.Code, "call %d", i)
			}
		})
	}
}
