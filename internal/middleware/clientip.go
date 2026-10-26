package middleware

import (
	"fmt"
	"net"

	"github.com/gin-gonic/gin"
)

// ConfigureClientIP sets how engine derives c.ClientIP(), which the per-IP
// rate limiter and session records key on.
//
// Only peers inside trustedProxyCIDRs (TRUSTED_PROXY_CIDRS) are treated as
// proxies. For such a peer, X-Forwarded-For is walked right to left and the
// first address outside the trusted ranges is used — load balancers such as
// the AWS ALB append the real client address to whatever the client sent, so
// the leftmost entries are client-supplied and never used. X-Real-IP is not
// consulted. With no CIDRs configured nothing is trusted and ClientIP() is
// always the TCP peer address.
//
// gin.New() trusts every peer by default, so every engine that serves
// requests must call this before it starts serving.
func ConfigureClientIP(engine *gin.Engine, trustedProxyCIDRs []*net.IPNet) error {
	engine.RemoteIPHeaders = []string{"X-Forwarded-For"}
	engine.TrustedPlatform = ""

	if len(trustedProxyCIDRs) == 0 {
		if err := engine.SetTrustedProxies(nil); err != nil {
			return fmt.Errorf("configure trusted proxies: %w", err)
		}
		return nil
	}

	proxies := make([]string, 0, len(trustedProxyCIDRs))
	for _, cidr := range trustedProxyCIDRs {
		if cidr == nil {
			return fmt.Errorf("configure trusted proxies: nil CIDR in trusted proxy list")
		}
		proxies = append(proxies, cidr.String())
	}
	if err := engine.SetTrustedProxies(proxies); err != nil {
		return fmt.Errorf("configure trusted proxies %v: %w", proxies, err)
	}
	return nil
}
