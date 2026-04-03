// Package auth implements the authentication service including
// password reset, registration, login, and session management.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	// resetTokenTTL is how long a password reset token remains valid.
	resetTokenTTL = 30 * time.Minute

	// resetTokenPrefix is the Redis key prefix for password reset tokens.
	resetTokenPrefix = "pw_reset:"

	// resetTokenBytes is the number of random bytes in a reset token (32 bytes = 64 hex chars).
	resetTokenBytes = 32

	// tokenBlockPrefix is the Redis key prefix for blocklisted access token JTIs.
	tokenBlockPrefix = "token_block:"
)

// Sentinel errors for authentication failures.
var (
	ErrInvalidCredentials = fmt.Errorf("invalid email or password: %w", api.ErrUnauthorized)
	ErrAccountLocked      = fmt.Errorf("account is locked: %w", api.ErrForbidden)
	ErrAccountSuspended   = fmt.Errorf("account is suspended: %w", api.ErrForbidden)
	ErrTokenExpired       = fmt.Errorf("token has expired: %w", api.ErrUnauthorized)
	ErrTokenRevoked       = fmt.Errorf("token has been revoked: %w", api.ErrUnauthorized)
)

// Service implements api.AuthService with Redis-backed password reset tokens
// and full login/logout/refresh functionality.
type Service struct {
	redis         *redis.Client
	logger        *zap.Logger
	users         UserRepository
	refreshTokens RefreshTokenRepository
	tokens        TokenProvider
	passwords     PasswordVerifier
}

// NewService creates a new auth Service.
// The users, refreshTokens, tokens, and passwords dependencies may be nil
// if only password-reset functionality is needed (they are required for login/logout).
func NewService(
	redisClient *redis.Client,
	logger *zap.Logger,
	users UserRepository,
	refreshTokens RefreshTokenRepository,
	tokens TokenProvider,
	passwords PasswordVerifier,
) *Service {
	return &Service{
		redis:         redisClient,
		logger:        logger,
		users:         users,
		refreshTokens: refreshTokens,
		tokens:        tokens,
		passwords:     passwords,
	}
}

// Login authenticates a user by email and password, returning a token pair on success.
// Returns generic ErrInvalidCredentials for both "not found" and "wrong password"
// to prevent user enumeration. Returns specific errors for locked/suspended accounts
// only after credentials are verified.
func (s *Service) Login(ctx context.Context, email, password string) (*api.AuthResult, error) {
	user, err := s.users.GetByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			s.logger.Debug("login attempt for unknown email", zap.String("email", email))
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("fetch user: %w", err)
	}

	match, err := s.passwords.Verify(password, user.PasswordHash)
	if err != nil {
		s.logger.Error("password verification failed", zap.Error(err))
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		s.logger.Debug("login attempt with wrong password", zap.String("user_id", user.ID))
		return nil, ErrInvalidCredentials
	}

	switch user.Status {
	case domain.UserStatusLocked:
		return nil, ErrAccountLocked
	case domain.UserStatusSuspended:
		return nil, ErrAccountSuspended
	}

	result, refreshSig, err := s.tokens.GenerateTokenPair(ctx, user.ID, user.Roles, domain.ClientTypeUser)
	if err != nil {
		return nil, fmt.Errorf("generate tokens: %w", err)
	}

	refreshToken := &domain.RefreshToken{
		Signature: refreshSig,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(s.tokens.RefreshTokenTTL()),
		CreatedAt: time.Now(),
	}
	if err := s.refreshTokens.Store(ctx, refreshToken); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	if err := s.users.UpdateLastLoginAt(ctx, user.ID, time.Now()); err != nil {
		s.logger.Error("failed to update last_login_at",
			zap.String("user_id", user.ID),
			zap.Error(err),
		)
	}

	return result, nil
}

// RefreshTokens exchanges a refresh token for a new token pair using strict rotation.
// If a revoked token is presented (reuse detection), all tokens for the user are revoked.
func (s *Service) RefreshTokens(ctx context.Context, rawRefreshToken string) (*api.AuthResult, error) {
	signature, err := s.tokens.ValidateRefreshToken(rawRefreshToken)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", api.ErrUnauthorized)
	}

	stored, err := s.refreshTokens.GetBySignature(ctx, signature)
	if err != nil {
		if errors.Is(err, api.ErrNotFound) {
			return nil, fmt.Errorf("refresh token not found: %w", api.ErrUnauthorized)
		}
		return nil, fmt.Errorf("lookup refresh token: %w", err)
	}

	// Reuse detection: if someone presents a revoked token, assume token theft
	// and revoke all tokens for the user.
	if stored.IsRevoked() {
		s.logger.Warn("refresh token reuse detected, revoking all tokens",
			zap.String("user_id", stored.UserID),
			zap.String("signature", signature),
		)
		if revokeErr := s.refreshTokens.RevokeAllForUser(ctx, stored.UserID); revokeErr != nil {
			s.logger.Error("failed to revoke all tokens after reuse detection",
				zap.String("user_id", stored.UserID),
				zap.Error(revokeErr),
			)
		}
		return nil, ErrTokenRevoked
	}

	if stored.IsExpired() {
		return nil, ErrTokenExpired
	}

	if err := s.refreshTokens.Revoke(ctx, signature); err != nil {
		return nil, fmt.Errorf("revoke old refresh token: %w", err)
	}

	result, newSig, err := s.tokens.GenerateTokenPair(ctx, stored.UserID, nil, domain.ClientTypeUser)
	if err != nil {
		return nil, fmt.Errorf("generate new tokens: %w", err)
	}

	newToken := &domain.RefreshToken{
		Signature: newSig,
		UserID:    stored.UserID,
		ExpiresAt: time.Now().Add(s.tokens.RefreshTokenTTL()),
		CreatedAt: time.Now(),
	}
	if err := s.refreshTokens.Store(ctx, newToken); err != nil {
		return nil, fmt.Errorf("store new refresh token: %w", err)
	}

	return result, nil
}

// Register creates a new user account.
// Stub: full implementation depends on PostgreSQL user repository (future issue).
func (s *Service) Register(_ context.Context, email, _, name string) (*api.UserInfo, error) {
	return &api.UserInfo{
		ID:    "stub-user-id",
		Email: email,
		Name:  name,
	}, nil
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

	return nil
}

// ConfirmPasswordReset validates the reset token from Redis, updates the password,
// and revokes all sessions for the user.
func (s *Service) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	key := resetTokenPrefix + token

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
	return &api.UserInfo{
		ID:    userID,
		Email: "stub@example.com",
		Name:  "Stub User",
	}, nil
}

// ChangePassword changes the authenticated user's password.
// Stub: full implementation depends on PostgreSQL user repository.
func (s *Service) ChangePassword(_ context.Context, _, _, _ string) error {
	return fmt.Errorf("change password not yet implemented: %w", api.ErrInternalError)
}

// Logout terminates a single session by blocklisting the access token's JTI in Redis.
func (s *Service) Logout(ctx context.Context, _ /* userID */, rawToken string) error {
	jti, err := s.tokens.ExtractAccessTokenJTI(rawToken)
	if err != nil {
		return fmt.Errorf("extract token JTI: %w", api.ErrUnauthorized)
	}

	ttl := s.tokens.AccessTokenTTL()
	key := tokenBlockPrefix + jti
	if err := s.redis.Set(ctx, key, "1", ttl).Err(); err != nil {
		return fmt.Errorf("blocklist token: %w", err)
	}

	s.logger.Debug("access token blocklisted", zap.String("jti", jti))
	return nil
}

// LogoutAll terminates all sessions by revoking all refresh tokens for the user.
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	if err := s.refreshTokens.RevokeAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("revoke all refresh tokens: %w", err)
	}

	s.logger.Debug("all refresh tokens revoked", zap.String("user_id", userID))
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
