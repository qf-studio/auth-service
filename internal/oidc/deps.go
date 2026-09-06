package oidc

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// ClientLookup abstracts OAuth2 client retrieval. This is a narrow interface
// satisfied by storage.ClientRepository.
type ClientLookup interface {
	FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Client, error)
}

// UserLookup abstracts user retrieval. This is a narrow interface satisfied
// by storage.UserRepository (mirrors token.UserLookup).
type UserLookup interface {
	FindByID(ctx context.Context, tenantID uuid.UUID, id string) (*domain.User, error)
}

// TokenIssuer abstracts token minting. This is a narrow interface satisfied
// by *token.Service.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, audience ...string) (*api.AuthResult, error)
	IssueIDToken(ctx context.Context, subject, clientID, nonce string, authTime time.Time) (string, error)
}

// ConsentGrantStore abstracts remembered-consent persistence. This is a
// narrow interface satisfied by storage.ConsentGrantRepository.
type ConsentGrantStore interface {
	FindActive(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error)
	Create(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error)
}

// thirdPartyOwner marks clients created via the third-party approval
// workflow (ApprovalService.CreateThirdPartyClient). Clients created via the
// pre-existing admin.ClientService.CreateClient path are stamped
// Owner: "admin" and are treated as first-party (see isThirdParty).
//
// Decision: domain.Client has no dedicated first-party/approval column and
// this package may not add a migration for one, so first-party vs.
// third-party is distinguished via the existing Owner field instead. See
// GH-469.
const thirdPartyOwner = "third-party"

// isThirdParty reports whether client was created through the third-party
// approval workflow and therefore requires explicit user consent (as
// opposed to first-party clients, which are auto-consented).
func isThirdParty(client *domain.Client) bool {
	return client.Owner == thirdPartyOwner
}
