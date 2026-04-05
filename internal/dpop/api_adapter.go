package dpop

import (
	"context"

	"github.com/qf-studio/auth-service/internal/api"
)

// APIAdapter adapts a DPoP Service to the api.DPoPService interface
// used by the token handlers.
type APIAdapter struct {
	svc *Service
}

// NewAPIAdapter creates a new APIAdapter wrapping the given Service.
func NewAPIAdapter(svc *Service) *APIAdapter {
	return &APIAdapter{svc: svc}
}

// Enabled reports whether DPoP is active.
func (a *APIAdapter) Enabled() bool {
	return a.svc.Enabled()
}

// ValidateProof validates the proof and returns api.DPoPProofClaims.
func (a *APIAdapter) ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (*api.DPoPProofClaims, error) {
	claims, err := a.svc.ValidateProof(ctx, proofJWT, httpMethod, httpURI)
	if err != nil {
		return nil, err
	}
	return &api.DPoPProofClaims{
		JKTThumbprint: claims.JKTThumbprint,
		HTTPMethod:    claims.HTTPMethod,
		HTTPURI:       claims.HTTPURI,
	}, nil
}

// IssueNonce generates a server nonce.
func (a *APIAdapter) IssueNonce(ctx context.Context) (string, error) {
	return a.svc.IssueNonce(ctx)
}

// Ensure APIAdapter implements api.DPoPService at compile time.
var _ api.DPoPService = (*APIAdapter)(nil)
