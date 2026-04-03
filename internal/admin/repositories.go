// Package admin implements the admin service layer for user, client, and token management.
// Services depend on repository interfaces defined here — concrete implementations live in storage/.
package admin

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/domain"
)

// UserRepository defines the persistence operations required by the admin user service.
// Implementations should use storage.ErrNotFound for missing entities and
// storage.ErrDuplicateEmail for email uniqueness violations.
type UserRepository interface {
	// FindByID returns a user by ID (including soft-deleted). Returns storage.ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.User, error)

	// FindAll returns a paginated slice of users and the total count.
	// When includeDeleted is true, soft-deleted users are included.
	FindAll(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.User, int64, error)

	// Create inserts a new user. Returns storage.ErrDuplicateEmail on email collision.
	Create(ctx context.Context, user *domain.User) (*domain.User, error)

	// Update persists field changes to an existing user. Returns storage.ErrNotFound if absent.
	Update(ctx context.Context, user *domain.User) (*domain.User, error)

	// SoftDelete marks a user as deleted by setting deleted_at. Returns storage.ErrNotFound if absent.
	SoftDelete(ctx context.Context, id string) error

	// SetLocked updates the locked state, reason, and timestamp for a user.
	// Pass locked=false and a nil lockedAt to unlock. Returns storage.ErrNotFound if absent.
	SetLocked(ctx context.Context, id string, locked bool, reason string, lockedAt *time.Time) error
}

// ClientRepository defines the persistence operations required by the admin client service.
// Implementations should use storage.ErrNotFound for missing entities.
type ClientRepository interface {
	// FindByID returns a client by ID. Returns storage.ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.Client, error)

	// FindAll returns a paginated slice of clients and the total count.
	// When includeDeleted is true, revoked clients are included.
	FindAll(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.Client, int64, error)

	// Create inserts a new client. Returns storage.ErrDuplicateEmail on name uniqueness violation.
	Create(ctx context.Context, client *domain.Client) (*domain.Client, error)

	// Update persists field changes to an existing client. Returns storage.ErrNotFound if absent.
	Update(ctx context.Context, client *domain.Client) (*domain.Client, error)

	// Revoke marks a client as revoked (soft delete equivalent). Returns storage.ErrNotFound if absent.
	Revoke(ctx context.Context, id string) error
}

// TokenValidator validates a raw JWT access token (qf_at_ prefix already stripped)
// and returns its parsed claims. Implemented by token.Service.
type TokenValidator interface {
	ValidateToken(ctx context.Context, rawToken string) (*domain.TokenClaims, error)
}

// RefreshTokenFinder looks up a stored refresh token record by its full token string.
// Implemented by storage.PostgresRefreshTokenRepository.
type RefreshTokenFinder interface {
	FindBySignature(ctx context.Context, signature string) (*domain.RefreshTokenRecord, error)
}
