package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebAuthnRepository defines persistence operations for WebAuthn credentials.
type WebAuthnRepository interface {
	// CreateCredential stores a new WebAuthn credential.
	CreateCredential(ctx context.Context, cred *domain.WebAuthnCredential) error

	// GetCredentialsByUser returns all active credentials for a user.
	GetCredentialsByUser(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error)

	// GetCredentialByCredentialID retrieves a credential by its raw credential ID.
	// Returns ErrNotFound if no active credential matches.
	GetCredentialByCredentialID(ctx context.Context, credentialID []byte) (*domain.WebAuthnCredential, error)

	// UpdateSignCount updates the sign counter and last-used timestamp after login.
	UpdateSignCount(ctx context.Context, credentialID []byte, signCount uint32) error

	// DeleteCredential soft-deletes a credential by its UUID primary key,
	// scoped to the owning user. Returns ErrNotFound if not found.
	DeleteCredential(ctx context.Context, userID, id string) error
}
