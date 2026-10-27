package storage

import (
	"crypto/tls"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRedisOptions_TLS(t *testing.T) {
	tests := []struct {
		name       string
		addr       string
		useTLS     bool
		wantServer string
	}{
		{"plain", "redis.internal:6379", false, ""},
		{"tls with host:port", "redis.internal:6379", true, "redis.internal"},
		{"tls with bare host", "redis.internal", true, "redis.internal"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := redisOptions(tt.addr, "secret", 2, tt.useTLS)
			assert.Equal(t, tt.addr, opts.Addr)
			assert.Equal(t, "secret", opts.Password)
			assert.Equal(t, 2, opts.DB)

			if !tt.useTLS {
				assert.Nil(t, opts.TLSConfig)
				return
			}
			require.NotNil(t, opts.TLSConfig)
			assert.Equal(t, tt.wantServer, opts.TLSConfig.ServerName)
			assert.GreaterOrEqual(t, opts.TLSConfig.MinVersion, uint16(tls.VersionTLS12))
			assert.False(t, opts.TLSConfig.InsecureSkipVerify)
			assert.Nil(t, opts.TLSConfig.RootCAs, "nil RootCAs means system roots")
		})
	}
}
