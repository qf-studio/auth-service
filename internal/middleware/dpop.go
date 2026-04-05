package middleware

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// DPoPVerifier validates a DPoP proof JWT and returns the JWK thumbprint
// of the proof's embedded public key. The dpop package implements this
// interface. httpMethod and httpURL are the request's method and full URL,
// used to verify the htm and htu claims inside the proof.
type DPoPVerifier interface {
	VerifyProof(ctx context.Context, proofHeader, httpMethod, httpURL string) (thumbprint string, err error)
}

// DPoPMiddleware returns a Gin middleware that enforces DPoP
// proof-of-possession on DPoP-bound tokens. It must run AFTER
// AuthMiddleware so that *domain.TokenClaims is available in context.
//
// Behaviour:
//   - If the token has a cnf.jkt claim (DPoPThumbprint is set), the
//     request MUST include a valid DPoP header whose embedded public key
//     thumbprint matches the token's cnf.jkt. Returns 401 on missing
//     proof, invalid proof, or thumbprint mismatch.
//   - If the token has no cnf.jkt claim (plain Bearer), the middleware
//     passes through without requiring a DPoP header (backwards-compatible).
func DPoPMiddleware(verifier DPoPVerifier) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := GetClaims(c)
		if err != nil {
			// No claims means AuthMiddleware didn't run or failed;
			// let downstream handlers deal with it.
			c.Next()
			return
		}

		// Plain Bearer token — no DPoP binding required.
		if claims.DPoPThumbprint == "" {
			c.Next()
			return
		}

		// Token is DPoP-bound — require a valid proof header.
		proofHeader := c.GetHeader("DPoP")
		if proofHeader == "" {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"missing DPoP proof header for bound token")
			return
		}

		thumbprint, err := verifier.VerifyProof(
			c.Request.Context(),
			proofHeader,
			c.Request.Method,
			requestURL(c.Request),
		)
		if err != nil {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"invalid DPoP proof")
			return
		}

		if thumbprint != claims.DPoPThumbprint {
			domain.RespondWithError(c, http.StatusUnauthorized, domain.CodeUnauthorized,
				"DPoP proof key does not match token binding")
			return
		}

		c.Next()
	}
}

// requestURL reconstructs the full request URL used for htm/htu verification.
func requestURL(r *http.Request) string {
	scheme := "https"
	if r.TLS == nil {
		scheme = "http"
	}
	return scheme + "://" + r.Host + r.RequestURI
}
