// Package auth implements the authentication service including
// password reset, registration, login, and session management.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
)

const (
	// resetTokenTTL is how long a password reset token remains valid.
	resetTokenTTL = 30 * time.Minute

	// resetTokenPrefix is the Redis key prefix for password reset tokens.
	resetTokenPrefix = "pw_reset:"

	// resetTokenBytes is the number of random bytes in a reset token (32 bytes = 64 hex chars).
	resetTokenBytes = 32
)

// Service implements api.AuthService with Redis-backed password reset tokens.
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new auth Service.
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
	}
}

// Register creates a new user account.
// Stub: full implementation depends on PostgreSQL user repository (future issue).
func (s *Service) Register(_ context.Context, email, _, name string) (*api.UserInfo, error) {
	// TODO(GH-XX): wire PostgreSQL user repository for persistence.
	return &api.UserInfo{
		ID:    "stub-user-id",
		Email: email,
		Name:  name,
	}, nil
}

// Login authenticates a user by email and password.
// Stub: full implementation depends on PostgreSQL user repository and Argon2 hashing (future issue).
func (s *Service) Login(_ context.Context, _, _ string) (*api.AuthResult, error) {
	// TODO(GH-XX): wire PostgreSQL user repository + password verification + JWT issuance.
	return nil, fmt.Errorf("login not yet implemented: %w", api.ErrInternalError)
}

// ResetPassword initiates a password reset by generating a token, storing it in Redis,
// and (in future) sending an email. Returns nil even if the email doesn't exist to
// prevent enumeration.
func (s *Service) ResetPassword(ctx context.Context, email string) error {
	token, err := generateResetToken()
	if err != nil {
		s.logger.Error("failed to generate reset token", zap.Error(err))
		return fmt.Errorf("generate reset token: %w", err)
	}

	key := resetTokenPrefix + token
	if err := s.redis.Set(ctx, key, email, resetTokenTTL).Err(); err != nil {
		s.logger.Error("failed to store reset token in redis", zap.Error(err))
		return fmt.Errorf("store reset token: %w", err)
	}

	s.logger.Info("password reset token created",
		zap.String("email", email),
		zap.Duration("ttl", resetTokenTTL),
	)

	// TODO(GH-XX): send email with reset link containing the token.

	return nil
}

// ConfirmPasswordReset validates the reset token from Redis, updates the password,
// and revokes all sessions for the user.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	key := resetTokenPrefix + token

	// Retrieve and delete the token atomically.
	email, err := s.redis.GetDel(ctx, key).Result()
	if err == redis.Nil {
		return fmt.Errorf("invalid or expired reset token: %w", api.ErrUnauthorized)
	}
	if err != nil {
		s.logger.Error("failed to retrieve reset token from redis", zap.Error(err))
		return fmt.Errorf("retrieve reset token: %w", err)
	}

	// TODO(GH-XX): hash newPassword with Argon2id and update in PostgreSQL.
	// TODO(GH-XX): revoke all sessions for this user.
	_ = newPassword

	s.logger.Info("password reset confirmed", zap.String("email", email))

	return nil
}

// GetMe returns the current user's profile.
// Stub: full implementation depends on PostgreSQL user repository.
func (s *Service) GetMe(_ context.Context, userID string) (*api.UserInfo, error) {
	// TODO(GH-XX): wire PostgreSQL user repository.
	return &api.UserInfo{
		ID:    userID,
		Email: "stub@example.com",
		Name:  "Stub User",
	}, nil
}

// ChangePassword changes the authenticated user's password.
// Stub: full implementation depends on PostgreSQL user repository.
func (s *Service) ChangePassword(_ context.Context, _, _, _ string) error {
	// TODO(GH-XX): wire PostgreSQL user repository + Argon2 verification.
	return fmt.Errorf("change password not yet implemented: %w", api.ErrInternalError)
}

// Logout terminates a single session for the user.
// Stub: full implementation depends on session/token revocation store.
func (s *Service) Logout(_ context.Context, _, _ string) error {
	// TODO(GH-XX): wire session revocation.
	return nil
}

// LogoutAll terminates all sessions for the user.
// Stub: full implementation depends on session/token revocation store.
func (s *Service) LogoutAll(_ context.Context, _ string) error {
	// TODO(GH-XX): wire session revocation.
	return nil
}

// generateResetToken produces a cryptographically random hex-encoded token.
func generateResetToken() (string, error) {
	b := make([]byte, resetTokenBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}
