package dpop

import (
	"context"

	"github.com/qf-studio/auth-service/internal/middleware"
)

// MiddlewareAdapter adapts dpop.Service to satisfy middleware.DPoPVerifier.
type MiddlewareAdapter struct {
	svc *Service
}

// NewMiddlewareAdapter creates an adapter that bridges dpop.Service to middleware.DPoPVerifier.
func NewMiddlewareAdapter(svc *Service) *MiddlewareAdapter {
	return &MiddlewareAdapter{svc: svc}
}

// Enabled reports whether DPoP is enabled.
func (a *MiddlewareAdapter) Enabled() bool {
	return a.svc.Enabled()
}

// ValidateProof validates a DPoP proof and returns the result in the middleware-expected type.
func (a *MiddlewareAdapter) ValidateProof(ctx context.Context, proof, httpMethod, httpURI string) (*middleware.DPoPProofResult, error) {
	claims, err := a.svc.ValidateProof(ctx, proof, httpMethod, httpURI)
	if err != nil {
		return nil, err
	}
	return &middleware.DPoPProofResult{
		JWKThumbprint: claims.JWKThumbprint,
	}, nil
}

// Compile-time interface check.
var _ middleware.DPoPVerifier = (*MiddlewareAdapter)(nil)
