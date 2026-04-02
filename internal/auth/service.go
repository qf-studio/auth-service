package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"time"

	redispkg "github.com/qf-studio/auth-service/internal/redis"
)

const (
	// resetTokenPrefix is prepended to raw reset tokens for leak detection.
	resetTokenPrefix = "qf_pr_"
	// resetTokenBytes is the number of random bytes (256-bit).
	resetTokenBytes = 32
	// resetTokenTTL is how long a reset token is valid.
	resetTokenTTL = 1 * time.Hour
)

// UserRepository defines persistence operations the auth service needs for users.
type UserRepository interface {
	// GetByEmail returns the user ID and current password hash for the given email.
	// Returns ("", "", ErrUserNotFound) if no user matches.
	GetByEmail(ctx context.Context, email string) (userID string, passwordHash string, err error)
	// UpdatePasswordHash sets a new password hash for the given user ID.
	UpdatePasswordHash(ctx context.Context, userID string, newHash string) error
}

// RefreshTokenRevoker can revoke all refresh tokens for a user.
type RefreshTokenRevoker interface {
	RevokeAllForUser(ctx context.Context, userID string) error
}

// ErrUserNotFound is returned when no user matches the lookup criteria.
var ErrUserNotFound = errors.New("user not found")

// ErrInvalidResetToken is returned when a reset token is invalid or expired.
var ErrInvalidResetToken = errors.New("invalid or expired reset token")

// ErrWeakPassword is returned when the new password doesn't meet NIST policy.
var ErrWeakPassword = errors.New("password does not meet minimum length requirement")

// Service implements password reset business logic.
type Service struct {
	users      UserRepository
	tokens     redispkg.TokenStore
	limiter    redispkg.RateLimiter
	revoker    RefreshTokenRevoker
	devMode    bool
}

// NewService creates a new auth Service.
func NewService(users UserRepository, tokens redispkg.TokenStore, limiter redispkg.RateLimiter, revoker RefreshTokenRevoker) *Service {
	devMode := os.Getenv("APP_ENV") == "development"
	return &Service{
		users:   users,
		tokens:  tokens,
		limiter: limiter,
		revoker: revoker,
		devMode: devMode,
	}
}

// RequestPasswordReset generates a reset token for the given email.
// Always returns nil to prevent email enumeration.
func (s *Service) RequestPasswordReset(ctx context.Context, email string) error {
	// Rate-limit check first — even for non-existent emails to avoid timing leaks.
	if _, err := s.limiter.Allow(ctx, email); err != nil {
		if errors.Is(err, redispkg.ErrRateLimited) {
			// Silently swallow — don't reveal rate limiting to prevent enumeration.
			return nil
		}
		// Log internal errors but still return nil.
		log.Printf("rate limiter error for %s: %v", email, err)
		return nil
	}

	// Look up user — if not found, return nil silently.
	userID, _, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, ErrUserNotFound) {
			return nil
		}
		log.Printf("user lookup error for %s: %v", email, err)
		return nil
	}

	// Generate 256-bit random token with prefix.
	rawBytes := make([]byte, resetTokenBytes)
	if _, err := rand.Read(rawBytes); err != nil {
		log.Printf("token generation error: %v", err)
		return nil
	}
	rawToken := resetTokenPrefix + hex.EncodeToString(rawBytes)

	// SHA-256 hash for storage — never store the raw token.
	tokenHash := sha256Hash(rawToken)

	// Store hash(token) -> userID in Redis with TTL.
	if err := s.tokens.Store(ctx, tokenHash, userID, resetTokenTTL); err != nil {
		log.Printf("token store error: %v", err)
		return nil
	}

	// In dev mode, log the token to console (email-service placeholder).
	if s.devMode {
		log.Printf("[DEV] Password reset token for %s: %s", email, rawToken)
	}

	return nil
}

// ConfirmPasswordReset validates the token, updates the password, and revokes sessions.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	// Validate password length against NIST policy.
	if len(newPassword) < nistMinPasswordLength {
		return ErrWeakPassword
	}

	// Hash the incoming token to look up in Redis.
	tokenHash := sha256Hash(token)

	// Retrieve user ID from token store.
	userID, err := s.tokens.Retrieve(ctx, tokenHash)
	if err != nil {
		if errors.Is(err, redispkg.ErrTokenNotFound) {
			return ErrInvalidResetToken
		}
		return fmt.Errorf("retrieve reset token: %w", err)
	}

	// Hash the new password with Argon2id.
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("hash password: %w", err)
	}

	// Update password in DB.
	if err := s.users.UpdatePasswordHash(ctx, userID, passwordHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Delete the used token (single-use).
	if err := s.tokens.Delete(ctx, tokenHash); err != nil && !errors.Is(err, redispkg.ErrTokenNotFound) {
		log.Printf("delete reset token warning: %v", err)
	}

	// Revoke all refresh tokens for the user.
	if err := s.revoker.RevokeAllForUser(ctx, userID); err != nil {
		log.Printf("revoke refresh tokens warning for user %s: %v", userID, err)
	}

	return nil
}

// nistMinPasswordLength mirrors the domain constant for internal validation.
const nistMinPasswordLength = 15

// sha256Hash returns the hex-encoded SHA-256 hash of the input string.
func sha256Hash(input string) string {
	h := sha256.Sum256([]byte(input))
	return hex.EncodeToString(h[:])
}
