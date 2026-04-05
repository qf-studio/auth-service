package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebAuthnCredentialRepository defines persistence operations for WebAuthn credentials.
type WebAuthnCredentialRepository interface {
	// CreateCredential stores a new WebAuthn credential.
	CreateCredential(ctx context.Context, cred *domain.WebAuthnCredential) error

	// GetCredentialsByUser returns all credentials for a user.
	GetCredentialsByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)

	// GetCredentialByCredentialID returns a credential by its raw credential ID.
	// Returns ErrNotFound if no credential with that ID exists.
	GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error)

	// UpdateSignCount updates the sign count and clone warning flag for a credential.
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32, cloneWarning bool) error

	// DeleteCredential removes a credential by its primary key ID.
	// Returns ErrNotFound if no credential with that ID exists.
	DeleteCredential(ctx context.Context, id string) error
}
