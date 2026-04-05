package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// dpopThumbprintKey is the Gin context key where the DPoP JWK thumbprint is stored.
const dpopThumbprintKey = "dpop_thumbprint"

// DPoPVerifier defines the operations required by DPoPMiddleware.
// dpop.Service implements this interface.
type DPoPVerifier interface {
	// Enabled reports whether DPoP validation is active.
	Enabled() bool

	// ValidateProof validates a DPoP proof JWT and returns its claims.
	ValidateProof(ctx context.Context, proof, httpMethod, httpURI string) (*DPoPProofResult, error)
}

// DPoPProofResult is a minimal struct for middleware use, matching dpop.ProofClaims.
type DPoPProofResult struct {
	JWKThumbprint string
}

// DPoPMiddleware returns a Gin middleware that enforces DPoP proof-of-possession
// on protected endpoints. It runs after AuthMiddleware.
//
// Behavior:
//   - If the authenticated token has a cnf.jkt claim (DPoP-bound), a valid DPoP
//     proof header is required and its JWK thumbprint must match the token's cnf.jkt.
//   - If the token has no cnf.jkt claim, the request passes through (backwards-compatible
//     with plain Bearer tokens).
//   - If DPoP is disabled, the middleware is a no-op.
func DPoPMiddleware(verifier DPoPVerifier, requestURIFn func(*gin.Context) string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !verifier.Enabled() {
			c.Next()
			return
		}

		// Retrieve claims set by AuthMiddleware.
		claims, err := GetClaims(c)
		if err != nil {
			// No claims = not authenticated yet (e.g., public endpoints).
			// Let the request through; auth middleware will handle rejection.
			c.Next()
			return
		}

		// If the token is not DPoP-bound, allow plain Bearer usage.
		if claims.JWKThumbprint == "" {
			c.Next()
			return
		}

		// Token is DPoP-bound — require proof.
		dpopHeader := c.GetHeader("DPoP")
		if dpopHeader == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP proof required for DPoP-bound token")
			return
		}

		httpURI := requestURIFn(c)
		result, err := verifier.ValidateProof(c.Request.Context(), dpopHeader, c.Request.Method, httpURI)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid DPoP proof: "+err.Error())
			return
		}

		// Verify the proof's JWK thumbprint matches the token's cnf.jkt.
		if result.JWKThumbprint != claims.JWKThumbprint {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP proof key does not match token binding")
			return
		}

		c.Set(dpopThumbprintKey, result.JWKThumbprint)
		c.Next()
	}
}

// GetDPoPThumbprint retrieves the validated DPoP JWK thumbprint from the Gin context.
// Returns empty string if not present (non-DPoP request).
func GetDPoPThumbprint(c *gin.Context) string {
	v, _ := c.Get(dpopThumbprintKey)
	s, _ := v.(string)
	return s
}
