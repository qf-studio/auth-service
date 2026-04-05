package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebAuthnRepository defines persistence operations for WebAuthn credentials.
type WebAuthnRepository interface {
	// Create stores a new WebAuthn credential.
	Create(ctx context.Context, cred *domain.WebAuthnCredential) (*domain.WebAuthnCredential, error)

	// GetByUser returns all active (non-deleted) credentials for a user.
	GetByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)

	// GetByCredentialID retrieves a single active credential by its raw credential ID.
	// Returns ErrNotFound if no matching active credential exists.
	GetByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error)

	// UpdateSignCount atomically updates the signature counter for clone detection.
	// Returns ErrNotFound if the credential does not exist or is deleted.
	UpdateSignCount(ctx context.Context, id string, newCount uint32) error

	// Delete hard-deletes a credential by internal ID.
	// Returns ErrNotFound if the credential does not exist.
	Delete(ctx context.Context, id string) error

	// SoftDelete marks a credential as deleted without removing the row.
	// Returns ErrNotFound if the credential is already deleted or does not exist.
	SoftDelete(ctx context.Context, id string) error
}
