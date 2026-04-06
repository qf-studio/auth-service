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
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/hibp"
	"github.com/qf-studio/auth-service/internal/password"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// resetTokenTTL is how long a password reset token remains valid.
	resetTokenTTL = 30 * time.Minute

	// resetTokenPrefix is the Redis key prefix for password reset tokens.
	resetTokenPrefix = "pw_reset:"

	// resetTokenBytes is the number of random bytes in a reset token (32 bytes = 64 hex chars).
	resetTokenBytes = 32
)

// TokenIssuer abstracts token pair creation for the auth service.
// This is a narrow interface satisfied by token.Service.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType) (*api.AuthResult, error)
	Revoke(ctx context.Context, token string) error
}

// MFAChecker abstracts MFA status checking and token generation.
// This is a narrow interface satisfied by mfa.Service.
type MFAChecker interface {
	IsMFAEnabled(ctx context.Context, userID string) (bool, error)
	GenerateMFAToken(ctx context.Context, userID string) (string, error)
}

// Service implements api.AuthService with Redis-backed password reset tokens
// and PostgreSQL-backed user authentication.
type Service struct {
	redis    *redis.Client
	logger   *zap.Logger
	audit    audit.EventLogger
	users    storage.UserRepository
	tokens   storage.RefreshTokenRepository
	issuer   TokenIssuer
	hasher   password.Hasher
	breaches hibp.BreachChecker
	mfa      MFAChecker
	policy   *password.PolicyValidator
}

// NewService creates a new auth Service.
func NewService(
	redisClient *redis.Client,
	logger *zap.Logger,
	auditor audit.EventLogger,
	users storage.UserRepository,
	tokens storage.RefreshTokenRepository,
	issuer TokenIssuer,
	hasher password.Hasher,
	breaches hibp.BreachChecker,
) *Service {
	return &Service{
		redis:    redisClient,
		logger:   logger,
		audit:    auditor,
		users:    users,
		tokens:   tokens,
		issuer:   issuer,
		hasher:   hasher,
		breaches: breaches,
		policy:   password.NewPolicyValidator(password.DefaultPolicy(), hasher),
	}
}

// SetPasswordPolicy replaces the default password policy validator.
func (s *Service) SetPasswordPolicy(pv *password.PolicyValidator) {
	s.policy = pv
}

// SetMFAChecker injects the MFA checker after construction to break the
// circular dependency between auth.Service and mfa.Service.
func (s *Service) SetMFAChecker(mfa MFAChecker) {
	s.mfa = mfa
}

// Register creates a new user account with policy-aware password validation.
func (s *Service) Register(ctx context.Context, email, pwd, name string) (*api.UserInfo, error) {
	if err := s.policy.ValidatePassword(pwd); err != nil {
		return nil, fmt.Errorf("password policy: %w", err)
	}

	hash, err := s.hasher.Hash(pwd)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:                fmt.Sprintf("usr_%s", generateID()),
		Email:             email,
		PasswordHash:      hash,
		Name:              name,
		Roles:             []string{"user"},
		PasswordChangedAt: &now,
		CreatedAt:         now,
		UpdatedAt:         now,
	}

	created, err := s.users.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	// Seed password history with initial hash.
	if s.policy.HistoryCount() > 0 {
		if histErr := s.users.AddPasswordHistory(ctx, created.ID, hash); histErr != nil {
			s.logger.Error("failed to seed password history", zap.String("user_id", created.ID), zap.Error(histErr))
		}
	}

	info := &api.UserInfo{
		ID:    created.ID,
		Email: created.Email,
		Name:  created.Name,
	}
	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventRegister,
		ActorID:  info.ID,
		TargetID: info.ID,
		Metadata: map[string]string{"email": email},
	})
	return info, nil
}

// Login authenticates a user by email and password.
// Returns a generic ErrUnauthorized for all failure modes to prevent user enumeration.
func (s *Service) Login(ctx context.Context, email, pwd string) (*api.AuthResult, error) {
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventLoginFailure,
				Metadata: map[string]string{"reason": "user_not_found"},
			})
			return nil, fmt.Errorf("invalid credentials: %w", api.ErrUnauthorized)
		}
		s.logger.Error("failed to find user by email", zap.Error(err))
		return nil, fmt.Errorf("find user: %w", err)
	}

	// Check account status before verifying password.
	if user.DeletedAt != nil {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventLoginFailure,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"reason": "account_suspended"},
		})
		return nil, fmt.Errorf("account suspended: %w", api.ErrUnauthorized)
	}
	if user.Locked {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventLoginFailure,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"reason": "account_locked"},
		})
		return nil, fmt.Errorf("account locked: %w", api.ErrUnauthorized)
	}

	match, err := s.hasher.Verify(pwd, user.PasswordHash)
	if err != nil {
		s.logger.Error("password verification error", zap.Error(err))
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventLoginFailure,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"reason": "invalid_password"},
		})
		return nil, fmt.Errorf("invalid credentials: %w", api.ErrUnauthorized)
	}

	// Transparent hash upgrade: re-hash bcrypt → argon2id on successful login.
	if s.hasher.NeedsUpgrade(user.PasswordHash) {
		newHash, hashErr := s.hasher.Hash(pwd)
		if hashErr != nil {
			s.logger.Error("failed to re-hash password", zap.String("user_id", user.ID), zap.Error(hashErr))
		} else {
			if upErr := s.users.UpdatePasswordHash(ctx, user.ID, newHash); upErr != nil {
				s.logger.Error("failed to persist upgraded hash", zap.String("user_id", user.ID), zap.Error(upErr))
			} else {
				s.audit.LogEvent(ctx, audit.Event{
					Type:     audit.EventHashUpgraded,
					ActorID:  user.ID,
					TargetID: user.ID,
					Metadata: map[string]string{"from": "bcrypt", "to": "argon2id"},
				})
			}
		}
	}

	// Check force_password_change flag.
	if user.ForcePasswordChange {
		return &api.AuthResult{
			UserID:              user.ID,
			ForcePasswordChange: true,
		}, nil
	}

	// Check password expiration.
	if s.policy.IsExpired(user.PasswordChangedAt) {
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventPasswordExpired,
			ActorID:  user.ID,
			TargetID: user.ID,
		})
		return &api.AuthResult{
			UserID:              user.ID,
			ForcePasswordChange: true,
		}, nil
	}

	// Check MFA status: if enabled, return challenge instead of tokens.
	if s.mfa != nil {
		mfaEnabled, mfaErr := s.mfa.IsMFAEnabled(ctx, user.ID)
		if mfaErr != nil {
			s.logger.Error("failed to check mfa status", zap.String("user_id", user.ID), zap.Error(mfaErr))
			// Continue with normal login on MFA check failure (fail-open for availability).
		} else if mfaEnabled {
			mfaToken, tokenErr := s.mfa.GenerateMFAToken(ctx, user.ID)
			if tokenErr != nil {
				s.logger.Error("failed to generate mfa token", zap.String("user_id", user.ID), zap.Error(tokenErr))
				return nil, fmt.Errorf("generate mfa token: %w", tokenErr)
			}
			s.audit.LogEvent(ctx, audit.Event{
				Type:     "mfa_challenge_issued",
				ActorID:  user.ID,
				TargetID: user.ID,
			})
			return &api.AuthResult{
				MFARequired: true,
				MFAToken:    mfaToken,
				UserID:      user.ID,
			}, nil
		}
	}

	// Issue token pair.
	result, err := s.issuer.IssueTokenPair(ctx, user.ID, user.Roles, nil, domain.ClientTypeUser)
	if err != nil {
		s.logger.Error("failed to issue token pair", zap.Error(err))
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	result.UserID = user.ID

	// Store refresh token signature in DB (best-effort — don't fail login).
	if err := s.tokens.Store(ctx, result.RefreshToken, user.ID, time.Now().Add(24*time.Hour)); err != nil {
		s.logger.Error("failed to store refresh token signature", zap.String("user_id", user.ID), zap.Error(err))
	}

	// Update last_login_at (best-effort — don't fail login).
	if err := s.users.UpdateLastLogin(ctx, user.ID, time.Now().UTC()); err != nil {
		s.logger.Error("failed to update last_login_at", zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventLoginSuccess,
		ActorID:  user.ID,
		TargetID: user.ID,
	})

	return result, nil
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

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventPasswordReset,
		Metadata: map[string]string{"email": email},
	})

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

	// Validate new password against policy.
	if err := s.policy.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password policy: %w", err)
	}

	// Find user to get current hash for history.
	user, err := s.users.FindByEmail(ctx, email)
	if err != nil {
		s.logger.Error("failed to find user for password reset", zap.String("email", email), zap.Error(err))
		return fmt.Errorf("find user: %w", err)
	}

	// Check password history for reuse.
	if s.policy.HistoryCount() > 0 {
		history, histErr := s.users.GetPasswordHistory(ctx, user.ID, s.policy.HistoryCount())
		if histErr != nil {
			s.logger.Error("failed to get password history", zap.String("user_id", user.ID), zap.Error(histErr))
		} else if reuseErr := s.policy.CheckHistory(newPassword, history); reuseErr != nil {
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventPasswordReused,
				ActorID:  user.ID,
				TargetID: user.ID,
			})
			return fmt.Errorf("password reuse: %w", reuseErr)
		}
	}

	// Hash new password.
	newHash, hashErr := s.hasher.Hash(newPassword)
	if hashErr != nil {
		return fmt.Errorf("hash new password: %w", hashErr)
	}

	// Save old hash to history.
	if s.policy.HistoryCount() > 0 {
		if histErr := s.users.AddPasswordHistory(ctx, user.ID, user.PasswordHash); histErr != nil {
			s.logger.Error("failed to add password history", zap.String("user_id", user.ID), zap.Error(histErr))
		}
	}

	// Update password hash in database.
	if err := s.users.UpdatePasswordHash(ctx, user.ID, newHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Revoke all sessions for this user.
	if err := s.tokens.RevokeAllForUser(ctx, user.ID); err != nil {
		s.logger.Error("failed to revoke sessions after password reset", zap.String("user_id", user.ID), zap.Error(err))
	}

	s.logger.Info("password reset confirmed", zap.String("email", email))

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventPasswordResetConfm,
		Metadata: map[string]string{"email": email},
	})

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
// Validates old password, checks policy, checks history, then updates.
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	user, err := s.users.FindByID(ctx, userID)
	if err != nil {
		return fmt.Errorf("find user: %w", err)
	}

	// Verify old password.
	match, err := s.hasher.Verify(oldPassword, user.PasswordHash)
	if err != nil {
		return fmt.Errorf("verify old password: %w", err)
	}
	if !match {
		return fmt.Errorf("old password incorrect: %w", api.ErrUnauthorized)
	}

	// Validate new password against policy.
	if err := s.policy.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password policy: %w", err)
	}

	// Check password history for reuse.
	if s.policy.HistoryCount() > 0 {
		history, histErr := s.users.GetPasswordHistory(ctx, userID, s.policy.HistoryCount())
		if histErr != nil {
			s.logger.Error("failed to get password history", zap.String("user_id", userID), zap.Error(histErr))
		} else if reuseErr := s.policy.CheckHistory(newPassword, history); reuseErr != nil {
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventPasswordReused,
				ActorID:  userID,
				TargetID: userID,
			})
			return fmt.Errorf("password reuse: %w", reuseErr)
		}
	}

	// Hash and store new password.
	newHash, err := s.hasher.Hash(newPassword)
	if err != nil {
		return fmt.Errorf("hash new password: %w", err)
	}

	// Save old hash to history before updating.
	if s.policy.HistoryCount() > 0 {
		if histErr := s.users.AddPasswordHistory(ctx, userID, user.PasswordHash); histErr != nil {
			s.logger.Error("failed to add password history", zap.String("user_id", userID), zap.Error(histErr))
		}
	}

	if err := s.users.UpdatePasswordHash(ctx, userID, newHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventPasswordChange,
		ActorID:  userID,
		TargetID: userID,
	})
	return nil
}

// Logout terminates a single session by revoking the access token via Redis
// blocklist and revoking the refresh token in the database.
func (s *Service) Logout(ctx context.Context, userID, token string) error {
	// Revoke the access token via Redis blocklist.
	if err := s.issuer.Revoke(ctx, token); err != nil {
		s.logger.Error("failed to revoke access token",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("revoke access token: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventLogout,
		ActorID:  userID,
		TargetID: userID,
	})

	s.logger.Info("session terminated", zap.String("user_id", userID))
	return nil
}

// LogoutAll terminates all sessions for the user by revoking all refresh tokens.
func (s *Service) LogoutAll(ctx context.Context, userID string) error {
	if err := s.tokens.RevokeAllForUser(ctx, userID); err != nil {
		s.logger.Error("failed to revoke all refresh tokens",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("revoke all sessions: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventLogoutAll,
		ActorID:  userID,
		TargetID: userID,
	})

	s.logger.Info("all sessions terminated", zap.String("user_id", userID))
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

// generateID produces a short random hex ID for user IDs.
func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
