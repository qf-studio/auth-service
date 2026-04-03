package auth

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

// UserRepository provides user data access for authentication.
type UserRepository interface {
	GetByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateLastLoginAt(ctx context.Context, userID string, t time.Time) error
}

// RefreshTokenRepository manages refresh token signatures in the database.
type RefreshTokenRepository interface {
	Store(ctx context.Context, token *domain.RefreshToken) error
	GetBySignature(ctx context.Context, signature string) (*domain.RefreshToken, error)
	Revoke(ctx context.Context, signature string) error
	RevokeAllForUser(ctx context.Context, userID string) error
}

// TokenProvider generates and validates tokens for authentication.
type TokenProvider interface {
	GenerateTokenPair(ctx context.Context, userID string, roles []string, clientType string) (result *api.AuthResult, refreshSig string, err error)
	ValidateRefreshToken(token string) (signature string, err error)
	ExtractAccessTokenJTI(rawToken string) (jti string, err error)
	AccessTokenTTL() time.Duration
	RefreshTokenTTL() time.Duration
}

// PasswordVerifier checks passwords against stored Argon2id hashes.
type PasswordVerifier interface {
	Verify(password, encodedHash string) (match bool, err error)
}
