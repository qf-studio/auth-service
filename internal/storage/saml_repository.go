package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SAMLIdentityRepository defines the persistence operations for linked SAML identities.
type SAMLIdentityRepository interface {
	// Create stores a new SAML identity link.
	Create(ctx context.Context, identity *domain.SAMLIdentity) (*domain.SAMLIdentity, error)

	// FindByIdPAndNameID returns the SAML identity for a given IdP entity ID and NameID.
	// Returns ErrNotFound if no matching identity exists.
	FindByIdPAndNameID(ctx context.Context, idpEntityID, nameID string) (*domain.SAMLIdentity, error)

	// FindByUserID returns all SAML identities linked to a user.
	FindByUserID(ctx context.Context, userID string) ([]domain.SAMLIdentity, error)

	// Delete removes the SAML identity link for a user and IdP.
	// Returns ErrNotFound if no matching identity exists.
	Delete(ctx context.Context, userID, idpEntityID string) error
}
