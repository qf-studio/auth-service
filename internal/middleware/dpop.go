package middleware

import (
	"context"
	"fmt"
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
func DPoPMiddleware(validator DPoPProofValidator, trustedProxies TrustedProxies) gin.HandlerFunc {
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

		httpURI := dpopRequestURI(c, trustedProxies)
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

// dpopRequestURI reconstructs the full request URI for DPoP htu matching.
// Scheme/host come from PublicSchemeHost, which only trusts
// X-Forwarded-Proto/-Host when the request came from trustedProxies
// (GH-508) — otherwise it falls back to Request.TLS / Request.Host.
func dpopRequestURI(c *gin.Context, trustedProxies TrustedProxies) string {
	scheme, host := PublicSchemeHost(c.Request, trustedProxies)
	return fmt.Sprintf("%s://%s%s", scheme, host, c.Request.URL.Path)
}
