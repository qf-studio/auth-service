package dpop

import "context"

// MiddlewareValidator adapts a DPoP Service to the DPoPProofValidator interface
// used by the DPoP middleware, which needs only the JKT thumbprint string.
type MiddlewareValidator struct {
	svc *Service
}

// NewMiddlewareValidator creates a new MiddlewareValidator wrapping the given Service.
func NewMiddlewareValidator(svc *Service) *MiddlewareValidator {
	return &MiddlewareValidator{svc: svc}
}

// Enabled reports whether DPoP is active.
func (v *MiddlewareValidator) Enabled() bool {
	return v.svc.Enabled()
}

// ValidateProof validates the proof and returns the JWK thumbprint.
func (v *MiddlewareValidator) ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (string, error) {
	claims, err := v.svc.ValidateProof(ctx, proofJWT, httpMethod, httpURI)
	if err != nil {
		return "", err
	}
	return claims.JKTThumbprint, nil
}
