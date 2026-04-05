package dpop

import (
	"context"

	"github.com/qf-studio/auth-service/internal/api"
)

// HandlerAdapter adapts dpop.Service to satisfy api.DPoPProofValidator.
type HandlerAdapter struct {
	svc *Service
}

// NewHandlerAdapter creates an adapter for use by API handlers.
func NewHandlerAdapter(svc *Service) *HandlerAdapter {
	return &HandlerAdapter{svc: svc}
}

// Enabled reports whether DPoP is enabled.
func (a *HandlerAdapter) Enabled() bool {
	return a.svc.Enabled()
}

// ValidateProof validates a DPoP proof and returns the JWK thumbprint.
func (a *HandlerAdapter) ValidateProof(ctx context.Context, proof, httpMethod, httpURI string) (string, error) {
	claims, err := a.svc.ValidateProof(ctx, proof, httpMethod, httpURI)
	if err != nil {
		return "", err
	}
	return claims.JWKThumbprint, nil
}

// Compile-time interface check.
var _ api.DPoPProofValidator = (*HandlerAdapter)(nil)
