package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// DPoPProofValidator defines the proof validation operations required by DPoPMiddleware.
type DPoPProofValidator interface {
	Enabled() bool
	ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (jktThumbprint string, err error)
}

// dpopProofValidator adapts the DPoP service to the DPoPProofValidator interface.
type dpopProofValidator struct {
	enabled       bool
	validateProof func(ctx context.Context, proofJWT, httpMethod, httpURI string) (string, error)
}

func (v *dpopProofValidator) Enabled() bool { return v.enabled }
func (v *dpopProofValidator) ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (string, error) {
	return v.validateProof(ctx, proofJWT, httpMethod, httpURI)
}

// DPoPMiddleware returns a Gin middleware that enforces DPoP proof-of-possession
// for DPoP-bound tokens. It runs after AuthMiddleware and:
//
//  1. Reads the claims set by AuthMiddleware
//  2. If the token has a cnf.jkt claim (DPoP-bound), requires a valid DPoP proof
//  3. Validates the proof's JWK thumbprint matches the token's cnf.jkt
//  4. Non-bound tokens (no cnf.jkt) pass through without DPoP check
//
// trustedProxyCIDRs controls when X-Forwarded-Proto / X-Forwarded-Host are
// honored while reconstructing the request URI for htu matching (see
// RequestURI); pass nil to trust nothing (default, pre-existing behavior).
func DPoPMiddleware(validator DPoPProofValidator, trustedProxyCIDRs []*net.IPNet) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			// No claims means AuthMiddleware didn't run or failed — skip DPoP check.
			c.Next()
			return
		}

		// If the token is not DPoP-bound, no proof is required.
		if claims.JKTThumbprint == "" {
			c.Next()
			return
		}

		// Token is DPoP-bound — require a valid DPoP proof.
		proofJWT := c.GetHeader("DPoP")
		if proofJWT == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP proof required for DPoP-bound token")
			return
		}

		if validator == nil || !validator.Enabled() {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP is not enabled on this server")
			return
		}

		httpURI := RequestURI(c, trustedProxyCIDRs)
		thumbprint, validateErr := validator.ValidateProof(c.Request.Context(), proofJWT, c.Request.Method, httpURI)
		if validateErr != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				fmt.Sprintf("invalid DPoP proof: %s", validateErr))
			return
		}

		// Verify the proof's JWK thumbprint matches the token's cnf.jkt.
		if thumbprint != claims.JKTThumbprint {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP proof key does not match token binding")
			return
		}

		c.Next()
	}
}

// RequestURI reconstructs the externally-visible scheme, host, and path for
// a request — used for DPoP htu matching (RFC 9449) and any other same-origin
// check that needs the URL the client actually addressed.
//
// c.Request.TLS is per-connection state: behind a TLS-terminating reverse
// proxy (e.g. an AWS ALB in front of auth.quantflow.studio) the container
// only ever sees a plaintext connection, so TLS is always nil and the naive
// reconstruction always yields "http://...". That mismatches any correctly
// signed DPoP proof, which the client builds against the public "https://"
// URL, and every DPoP-bound request is rejected.
//
// To fix this without trusting arbitrary clients to set their own scheme,
// X-Forwarded-Proto / X-Forwarded-Host are only honored when the immediate
// peer address (Request.RemoteAddr) falls within trustedProxyCIDRs — i.e.
// only for connections from proxies this deployment explicitly configured
// via TRUSTED_PROXY_CIDRS. With no trusted CIDRs configured (the default),
// behavior is unchanged: scheme comes from Request.TLS and host from
// Request.Host.
func RequestURI(c *gin.Context, trustedProxyCIDRs []*net.IPNet) string {
	scheme := "https"
	if c.Request.TLS == nil {
		scheme = "http"
	}
	host := c.Request.Host

	if isTrustedProxy(c.Request.RemoteAddr, trustedProxyCIDRs) {
		if fwdProto := c.GetHeader("X-Forwarded-Proto"); fwdProto != "" {
			scheme = fwdProto
		}
		if fwdHost := c.GetHeader("X-Forwarded-Host"); fwdHost != "" {
			host = fwdHost
		}
	}

	return fmt.Sprintf("%s://%s%s", scheme, host, c.Request.URL.Path)
}

// isTrustedProxy reports whether remoteAddr (host:port, or a bare host as
// used by some test harnesses) falls within one of trustedProxyCIDRs.
func isTrustedProxy(remoteAddr string, trustedProxyCIDRs []*net.IPNet) bool {
	if len(trustedProxyCIDRs) == 0 {
		return false
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return false
	}

	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}
	return false
}
