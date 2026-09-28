// Package auth implements the authentication service including
// password reset, registration, login, and session management.
package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/email"
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

	// verifyTokenTTL is how long an email verification token remains valid.
	verifyTokenTTL = 24 * time.Hour

	// emailChangeTokenTTL is how long an email-change confirmation token
	// (mailed to the new address) remains valid.
	emailChangeTokenTTL = 24 * time.Hour

	// emailRevertTokenTTL is how long an email-change revert token (mailed to
	// the original address) remains valid. Longer than the change token so a
	// user who doesn't check their old inbox promptly still has a window to
	// undo an unauthorized change after it's been confirmed.
	emailRevertTokenTTL = 7 * 24 * time.Hour

	// emailChangeRatePrefix is the Redis key prefix for the email-change
	// request rate limiter.
	emailChangeRatePrefix = "email_change_rl:"

	// emailChangeRateLimit is the maximum number of email-change requests
	// allowed per user per emailChangeRateWindow.
	emailChangeRateLimit = 3

	// emailChangeRateWindow is the window emailChangeRateLimit applies over.
	emailChangeRateWindow = time.Hour
)

// TokenIssuer abstracts token pair creation for the auth service.
// This is a narrow interface satisfied by token.Service.
type TokenIssuer interface {
	IssueTokenPair(ctx context.Context, subject string, roles, scopes []string, clientType domain.ClientType, audience ...string) (*api.AuthResult, error)
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
	redis         *redis.Client
	logger        *zap.Logger
	audit         audit.EventLogger
	users         storage.UserRepository
	tokens        storage.RefreshTokenRepository
	issuer        TokenIssuer
	hasher        password.Hasher
	breaches      hibp.BreachChecker
	mfa           MFAChecker
	policy        *password.PolicyValidator
	email         email.EmailSender
	resetURLBase  string
	verifyURLBase string

	// emailEnabled mirrors cfg.Email.Enabled: gates the startup warning and
	// the POST /auth/me/email 503 check below, since s.email is always
	// non-nil (a ConsoleSender is wired up in dev even when email delivery
	// is disabled — see cmd/server/main.go).
	emailEnabled              bool
	emailChangeConfirmURLBase string
	emailChangeRevertURLBase  string

	// refreshTokenTTL is the configured lifetime for newly stored refresh
	// token DB rows. Falls back to defaultRefreshTokenTTL when unset (e.g.
	// tests that don't configure it), matching the previous hardcoded value.
	refreshTokenTTL time.Duration
}

// defaultRefreshTokenTTL is used when ServiceDeps.RefreshTokenTTL is unset.
const defaultRefreshTokenTTL = 24 * time.Hour

// ServiceDeps groups the dependencies needed to construct a Service. Using a
// struct here keeps NewService's call sites readable now that email delivery
// has been added on top of the existing 8 constructor parameters.
type ServiceDeps struct {
	Redis         *redis.Client
	Logger        *zap.Logger
	Auditor       audit.EventLogger
	Users         storage.UserRepository
	Tokens        storage.RefreshTokenRepository
	Issuer        TokenIssuer
	Hasher        password.Hasher
	Breaches      hibp.BreachChecker
	Email         email.EmailSender
	ResetURLBase  string // base URL password-reset links are built from: "<ResetURLBase>?token=<token>"
	VerifyURLBase string // base URL email-verification links are built from: "<VerifyURLBase>?token=<token>"

	// EmailEnabled mirrors cfg.Email.Enabled. Needed because Email itself is
	// always non-nil (main.go wires a ConsoleSender when delivery is
	// disabled), so it can't be used to detect whether delivery is "really"
	// enabled for the EmailChangeConfirmURLBase/EmailChangeRevertURLBase
	// startup-warning and 503 checks below.
	EmailEnabled bool

	// EmailChangeConfirmURLBase and EmailChangeRevertURLBase back the
	// email-change confirm/revert links. Optional even when EmailEnabled is
	// true: if either is empty, NewService logs a startup warning and
	// RequestEmailChange returns ErrEmailChangeUnconfigured (503) until both
	// are set, but nothing else about startup or the rest of the API is
	// affected.
	EmailChangeConfirmURLBase string
	EmailChangeRevertURLBase  string

	// RefreshTokenTTL is the lifetime used for refresh token DB rows stored
	// at login. Should match the token service's configured refresh TTL
	// (cfg.JWT.RefreshTokenTTL) so the DB row doesn't outlive or expire
	// before the Redis-backed token it introspects for.
	RefreshTokenTTL time.Duration
}

// NewService creates a new auth Service.
func NewService(deps ServiceDeps) *Service {
	if deps.EmailEnabled && (deps.EmailChangeConfirmURLBase == "" || deps.EmailChangeRevertURLBase == "") && deps.Logger != nil {
		deps.Logger.Warn("email change confirm/revert URL bases are not configured; POST /auth/me/email will respond 503 until EMAIL_CHANGE_CONFIRM_URL_BASE and EMAIL_CHANGE_REVERT_URL_BASE are set")
	}

	return &Service{
		redis:                     deps.Redis,
		logger:                    deps.Logger,
		audit:                     deps.Auditor,
		users:                     deps.Users,
		tokens:                    deps.Tokens,
		issuer:                    deps.Issuer,
		hasher:                    deps.Hasher,
		breaches:                  deps.Breaches,
		email:                     deps.Email,
		resetURLBase:              deps.ResetURLBase,
		verifyURLBase:             deps.VerifyURLBase,
		emailEnabled:              deps.EmailEnabled,
		emailChangeConfirmURLBase: deps.EmailChangeConfirmURLBase,
		emailChangeRevertURLBase:  deps.EmailChangeRevertURLBase,
		refreshTokenTTL:           deps.RefreshTokenTTL,
		policy:                    password.NewPolicyValidator(password.DefaultPolicy(), deps.Hasher),
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
	tenantID := domain.TenantIDFromContext(ctx)

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
		TenantID:          tenantID,
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
		if histErr := s.users.AddPasswordHistory(ctx, tenantID, created.ID, hash); histErr != nil {
			s.logger.Error("failed to seed password history", zap.String("user_id", created.ID), zap.Error(histErr))
		}
	}

	// Issue an email-verification token and send the link. This is best-effort:
	// a failure to generate, persist, or send the token must not fail
	// registration — the account is fully usable unverified (see Login).
	s.issueEmailVerification(ctx, tenantID, created)

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

// issueEmailVerification generates a verification token, persists it with a
// 24h expiry, and emails the verification link. Every failure mode (token
// generation, persistence, or delivery) is logged and audited but swallowed —
// registration must succeed regardless, per GH-478.
func (s *Service) issueEmailVerification(ctx context.Context, tenantID uuid.UUID, user *domain.User) {
	token, err := generateResetToken()
	if err != nil {
		s.logger.Error("failed to generate email verify token", zap.String("user_id", user.ID), zap.Error(err))
		return
	}

	expiresAt := time.Now().UTC().Add(verifyTokenTTL)
	if err := s.users.SetEmailVerifyToken(ctx, tenantID, user.ID, token, expiresAt); err != nil {
		s.logger.Error("failed to persist email verify token", zap.String("user_id", user.ID), zap.Error(err))
		return
	}

	if s.email == nil {
		return
	}

	link := s.verifyURLBase + "?token=" + token
	msg := email.Message{
		To:      user.Email,
		Subject: "Verify your email",
		Body:    fmt.Sprintf("Use the link below to verify your email address:\n\n%s\n\nThis link expires in %s.", link, verifyTokenTTL),
	}
	if sendErr := s.email.Send(ctx, msg); sendErr != nil {
		s.logger.Error("failed to send email verification email", zap.String("user_id", user.ID), zap.Error(sendErr))
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventEmailVerifyEmailFailed,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"email": user.Email},
		})
	}
}

// VerifyEmail marks a user's email as verified using the token from the
// verification link. Idempotent: calling it again after success (e.g. the
// user double-clicks the link) still returns nil. Returns an error for any
// invalid or expired token; the handler maps all errors here to 400.
func (s *Service) VerifyEmail(ctx context.Context, token string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.ConsumeEmailVerifyToken(ctx, tenantID, token)
	if err != nil {
		return fmt.Errorf("verify email: %w", err)
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventEmailVerified,
		ActorID:  user.ID,
		TargetID: user.ID,
	})

	return nil
}

// Login authenticates a user by email and password.
// Returns a generic ErrUnauthorized for all failure modes to prevent user enumeration.
func (s *Service) Login(ctx context.Context, email, pwd string) (*api.AuthResult, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.FindByEmail(ctx, tenantID, email)
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
	// Note: user.EmailVerified is intentionally NOT checked here. In v1, email
	// verification is informational only (GH-478) — gating login on it would
	// block dogfood and design-partner signups whose links may go unclicked.
	// Do not add an EmailVerified check without a product decision to enforce it.
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
			if upErr := s.users.UpdatePasswordHash(ctx, tenantID, user.ID, newHash); upErr != nil {
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
			// Fail closed (NIST SP 800-63-4 AAL2): an MFA-status lookup error
			// must not silently downgrade an MFA-enrolled user to a
			// password-only (AAL1) login. An MFA-store outage blocks login
			// for MFA-enrolled users rather than letting the second factor
			// be bypassed by degrading the store (GH-488).
			s.audit.LogEvent(ctx, audit.Event{
				Type:     "mfa_status_check_failed",
				ActorID:  user.ID,
				TargetID: user.ID,
			})
			return nil, fmt.Errorf("check mfa status: %w", api.ErrInternalError)
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

	// Issue token pair. Password login (LoginRequest) carries no client_id —
	// there is no OAuth2 client context here to resolve a per-client
	// Audience from, so this always issues a global-JWT_AUDIENCE token
	// (GH-512). Products that need per-client audience isolation must use
	// the OIDC authorization code flow instead (see README.md's "Per-Client
	// Audience" section).
	result, err := s.issuer.IssueTokenPair(ctx, user.ID, user.Roles, nil, domain.ClientTypeUser)
	if err != nil {
		s.logger.Error("failed to issue token pair", zap.Error(err))
		return nil, fmt.Errorf("issue tokens: %w", err)
	}

	result.UserID = user.ID

	// Store refresh token signature in DB (best-effort — don't fail login).
	// Only the signature segment is persisted, never the full token
	// (GH-486): storing the full token broke introspection lookups, which
	// key on FindBySignature(parts[1]) alone.
	if sig, ok := domain.RefreshTokenSignature(result.RefreshToken); ok {
		ttl := s.refreshTokenTTL
		if ttl <= 0 {
			ttl = defaultRefreshTokenTTL
		}
		if err := s.tokens.Store(ctx, tenantID, sig, user.ID, time.Now().Add(ttl)); err != nil {
			s.logger.Error("failed to store refresh token signature", zap.String("user_id", user.ID), zap.Error(err))
		}
	} else {
		s.logger.Error("failed to parse refresh token signature, skipping DB store", zap.String("user_id", user.ID))
	}

	// Update last_login_at (best-effort — don't fail login).
	if err := s.users.UpdateLastLogin(ctx, tenantID, user.ID, time.Now().UTC()); err != nil {
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
// and emailing the reset link. Returns nil even if the email doesn't exist, and even if
// delivery fails, to prevent user enumeration via response timing/content.
func (s *Service) ResetPassword(ctx context.Context, emailAddr string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	// Look up the user first: unknown addresses skip both token storage and
	// send entirely, so no reset token is ever minted for an address that
	// isn't registered.
	if _, err := s.users.FindByEmail(ctx, tenantID, emailAddr); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			s.logger.Info("password reset requested for unknown email", zap.String("email", emailAddr))
			return nil
		}
		s.logger.Error("failed to look up user for password reset", zap.Error(err))
		return fmt.Errorf("find user: %w", err)
	}

	token, err := generateResetToken()
	if err != nil {
		s.logger.Error("failed to generate reset token", zap.Error(err))
		return fmt.Errorf("generate reset token: %w", err)
	}

	key := resetTokenPrefix + token
	if err := s.redis.Set(ctx, key, emailAddr, resetTokenTTL).Err(); err != nil {
		s.logger.Error("failed to store reset token in redis", zap.Error(err))
		return fmt.Errorf("store reset token: %w", err)
	}

	s.logger.Info("password reset token created",
		zap.String("email", emailAddr),
		zap.Duration("ttl", resetTokenTTL),
	)

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventPasswordReset,
		Metadata: map[string]string{"email": emailAddr},
	})

	if s.email != nil {
		link := s.resetURLBase + "?token=" + token
		msg := email.Message{
			To:      emailAddr,
			Subject: "Reset your password",
			Body:    fmt.Sprintf("Use the link below to reset your password:\n\n%s\n\nThis link expires in %s.", link, resetTokenTTL),
		}
		if sendErr := s.email.Send(ctx, msg); sendErr != nil {
			// Delivery failure must not become an enumeration oracle: log and
			// audit, but still return nil so the handler responds 202.
			s.logger.Error("failed to send password reset email", zap.Error(sendErr))
			s.audit.LogEvent(ctx, audit.Event{
				Type:     audit.EventPasswordResetEmailFailed,
				Metadata: map[string]string{"email": emailAddr},
			})
		}
	}

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

	tenantID := domain.TenantIDFromContext(ctx)

	// Validate new password against policy.
	if err := s.policy.ValidatePassword(newPassword); err != nil {
		return fmt.Errorf("password policy: %w", err)
	}

	// Find user to get current hash for history.
	user, err := s.users.FindByEmail(ctx, tenantID, email)
	if err != nil {
		s.logger.Error("failed to find user for password reset", zap.String("email", email), zap.Error(err))
		return fmt.Errorf("find user: %w", err)
	}

	// Check password history for reuse.
	if s.policy.HistoryCount() > 0 {
		history, histErr := s.users.GetPasswordHistory(ctx, tenantID, user.ID, s.policy.HistoryCount())
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
		if histErr := s.users.AddPasswordHistory(ctx, tenantID, user.ID, user.PasswordHash); histErr != nil {
			s.logger.Error("failed to add password history", zap.String("user_id", user.ID), zap.Error(histErr))
		}
	}

	// Update password hash in database.
	if err := s.users.UpdatePasswordHash(ctx, tenantID, user.ID, newHash); err != nil {
		return fmt.Errorf("update password: %w", err)
	}

	// Revoke all sessions for this user.
	if err := s.tokens.RevokeAllForUser(ctx, tenantID, user.ID); err != nil {
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
func (s *Service) GetMe(ctx context.Context, userID string) (*api.UserInfo, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.FindByID(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	return &api.UserInfo{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
	}, nil
}

// UpdateProfile updates the authenticated user's display name.
func (s *Service) UpdateProfile(ctx context.Context, userID, name string) (*api.UserInfo, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.FindByID(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("user not found: %w", api.ErrNotFound)
		}
		return nil, fmt.Errorf("find user: %w", err)
	}

	if err := s.users.UpdateName(ctx, tenantID, userID, name); err != nil {
		return nil, fmt.Errorf("update name: %w", err)
	}
	user.Name = name

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventProfileUpdated,
		ActorID:  userID,
		TargetID: userID,
	})

	return &api.UserInfo{
		ID:    user.ID,
		Email: user.Email,
		Name:  user.Name,
	}, nil
}

// ChangePassword changes the authenticated user's password.
// Validates old password, checks policy, checks history, then updates.
func (s *Service) ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.FindByID(ctx, tenantID, userID)
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
		history, histErr := s.users.GetPasswordHistory(ctx, tenantID, userID, s.policy.HistoryCount())
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
		if histErr := s.users.AddPasswordHistory(ctx, tenantID, userID, user.PasswordHash); histErr != nil {
			s.logger.Error("failed to add password history", zap.String("user_id", userID), zap.Error(histErr))
		}
	}

	if err := s.users.UpdatePasswordHash(ctx, tenantID, userID, newHash); err != nil {
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
// blocklist and, when a refresh token is supplied, marking its DB row
// revoked so introspection reflects the logout (GH-486). The refresh token
// is optional and best-effort: its absence or a DB failure must not fail
// the logout, since the Redis blocklist entry is the primary revocation
// signal for the access token itself.
func (s *Service) Logout(ctx context.Context, userID, token, refreshToken string) error {
	// Revoke the access token via Redis blocklist.
	if err := s.issuer.Revoke(ctx, token); err != nil {
		s.logger.Error("failed to revoke access token",
			zap.String("user_id", userID),
			zap.Error(err),
		)
		return fmt.Errorf("revoke access token: %w", err)
	}

	if refreshToken != "" {
		if sig, ok := domain.RefreshTokenSignature(refreshToken); ok {
			tenantID := domain.TenantIDFromContext(ctx)
			if err := s.tokens.Revoke(ctx, tenantID, sig); err != nil {
				s.logger.Warn("failed to revoke refresh token on logout",
					zap.String("user_id", userID),
					zap.Error(err),
				)
			}
		} else {
			s.logger.Warn("logout: malformed refresh token, skipping DB revoke",
				zap.String("user_id", userID))
		}
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
	tenantID := domain.TenantIDFromContext(ctx)

	if err := s.tokens.RevokeAllForUser(ctx, tenantID, userID); err != nil {
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

// RequestEmailChange initiates a change of the authenticated user's account
// email. The new address must be confirmed via a link mailed to it before
// the change takes effect (see ConfirmEmailChange); a link mailed to the
// current address allows reverting the change (see RevertEmailChange), since
// an email change is an account-takeover lever. Rate limited to
// emailChangeRateLimit requests per emailChangeRateWindow per user — every
// call counts against the limit, including ones that go on to fail the
// password check, so the limit can't be bypassed by guessing passwords. A
// second request while one is already pending replaces both pending tokens.
func (s *Service) RequestEmailChange(ctx context.Context, userID, newEmail, pwd string) (*api.EmailChangeResult, error) {
	tenantID := domain.TenantIDFromContext(ctx)

	if s.emailEnabled && (s.emailChangeConfirmURLBase == "" || s.emailChangeRevertURLBase == "") {
		return nil, fmt.Errorf("email change confirm/revert URL bases not configured: %w", api.ErrEmailChangeUnconfigured)
	}

	// Count every request against the per-user rate limit before doing any
	// other work, including the password check — otherwise an attacker can
	// probe passwords indefinitely by supplying a wrong one each time, since
	// a failed password check would never trip the limiter.
	allowed, err := s.checkEmailChangeRateLimit(ctx, tenantID, userID)
	if err != nil {
		s.logger.Error("failed to check email change rate limit", zap.String("user_id", userID), zap.Error(err))
		return nil, fmt.Errorf("check rate limit: %w", err)
	}
	if !allowed {
		return nil, fmt.Errorf("too many email change requests: %w", api.ErrRateLimited)
	}

	user, err := s.users.FindByID(ctx, tenantID, userID)
	if err != nil {
		return nil, fmt.Errorf("find user: %w", err)
	}

	match, err := s.hasher.Verify(pwd, user.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("verify password: %w", err)
	}
	if !match {
		return nil, fmt.Errorf("password incorrect: %w", api.ErrInvalidPassword)
	}

	if strings.EqualFold(newEmail, user.Email) {
		return nil, fmt.Errorf("new email matches current email: %w", api.ErrConflict)
	}

	if existing, findErr := s.users.FindByEmail(ctx, tenantID, newEmail); findErr == nil {
		if existing.ID != userID {
			return nil, fmt.Errorf("email already in use: %w", api.ErrConflict)
		}
	} else if !errors.Is(findErr, storage.ErrNotFound) {
		return nil, fmt.Errorf("find user by email: %w", findErr)
	}

	changeToken, err := generateResetToken()
	if err != nil {
		return nil, fmt.Errorf("generate change token: %w", err)
	}
	revertToken, err := generateResetToken()
	if err != nil {
		return nil, fmt.Errorf("generate revert token: %w", err)
	}

	now := time.Now().UTC()
	if err := s.users.SetPendingEmailChange(ctx, tenantID, userID, newEmail, changeToken, now.Add(emailChangeTokenTTL), revertToken, now.Add(emailRevertTokenTTL)); err != nil {
		return nil, fmt.Errorf("set pending email change: %w", err)
	}

	s.sendEmailChangeEmails(ctx, user, newEmail, changeToken, revertToken)

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventEmailChangeRequested,
		ActorID:  userID,
		TargetID: userID,
		Metadata: map[string]string{"new_email": newEmail},
	})

	return &api.EmailChangeResult{Status: "pending", PendingEmail: newEmail}, nil
}

// checkEmailChangeRateLimit increments a per-tenant-per-user Redis counter
// and (re)sets its 1-hour expiry in a single pipeline on every call — the
// same INCR+EXPIRE-together pattern AccountRateLimiter.RecordFailure uses —
// so the key can never end up persisted without a TTL (e.g. if a crash landed
// between two separate round trips). Reports whether the caller is still
// under emailChangeRateLimit.
func (s *Service) checkEmailChangeRateLimit(ctx context.Context, tenantID uuid.UUID, userID string) (bool, error) {
	key := fmt.Sprintf("%s%s:%s", emailChangeRatePrefix, tenantID, userID)

	pipe := s.redis.Pipeline()
	incrCmd := pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, emailChangeRateWindow)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, fmt.Errorf("check rate limit: %w", err)
	}

	return incrCmd.Val() <= emailChangeRateLimit, nil
}

// sendEmailChangeEmails sends the two notification emails for a requested
// email change: a confirmation link to the new address, and a revert link
// (naming only the new address's domain, not the full address) to the
// current one. Send failures are logged and audited but otherwise swallowed
// — the request has already succeeded and been persisted.
func (s *Service) sendEmailChangeEmails(ctx context.Context, user *domain.User, newEmail, changeToken, revertToken string) {
	if s.email == nil {
		return
	}

	changeLink := s.emailChangeConfirmURLBase + "?token=" + changeToken
	newMsg := email.Message{
		To:      newEmail,
		Subject: "Confirm your new email",
		Body:    fmt.Sprintf("Use the link below to confirm this is your new email address:\n\n%s\n\nThis link expires in %s.", changeLink, emailChangeTokenTTL),
	}
	if sendErr := s.email.Send(ctx, newMsg); sendErr != nil {
		s.logger.Error("failed to send email change confirmation email", zap.String("user_id", user.ID), zap.Error(sendErr))
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventEmailChangeEmailFailed,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"email": newEmail, "stage": "confirm"},
		})
	}

	revertLink := s.emailChangeRevertURLBase + "?token=" + revertToken
	oldMsg := email.Message{
		To:      user.Email,
		Subject: "Your email is being changed",
		Body: fmt.Sprintf(
			"Your account email is being changed to a new address at %s.\n\nIf you did not request this, use the link below to revert it:\n\n%s\n\nThis link expires in %s.",
			emailDomain(newEmail), revertLink, emailRevertTokenTTL,
		),
	}
	if sendErr := s.email.Send(ctx, oldMsg); sendErr != nil {
		s.logger.Error("failed to send email change notice email", zap.String("user_id", user.ID), zap.Error(sendErr))
		s.audit.LogEvent(ctx, audit.Event{
			Type:     audit.EventEmailChangeEmailFailed,
			ActorID:  user.ID,
			TargetID: user.ID,
			Metadata: map[string]string{"email": user.Email, "stage": "revert"},
		})
	}
}

// emailDomain returns the domain portion of an email address, or the whole
// string unchanged if it doesn't contain "@".
func emailDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 && i+1 < len(addr) {
		return addr[i+1:]
	}
	return addr
}

// ConfirmEmailChange completes a pending email change using the token mailed
// to the new address by RequestEmailChange. Revokes all sessions since the
// account's email — a primary recovery/identity credential — has changed.
func (s *Service) ConfirmEmailChange(ctx context.Context, token string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.ConsumeEmailChangeToken(ctx, tenantID, token)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			return fmt.Errorf("email change token: %w", api.ErrNotFound)
		case errors.Is(err, storage.ErrTokenExpired):
			return fmt.Errorf("email change token expired: %w", api.ErrGone)
		case errors.Is(err, storage.ErrDuplicateEmail):
			return fmt.Errorf("email already in use: %w", api.ErrConflict)
		default:
			return fmt.Errorf("confirm email change: %w", err)
		}
	}

	if err := s.tokens.RevokeAllForUser(ctx, tenantID, user.ID); err != nil {
		s.logger.Error("failed to revoke sessions after email change", zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventEmailChanged,
		ActorID:  user.ID,
		TargetID: user.ID,
		Metadata: map[string]string{"email": user.Email},
	})

	return nil
}

// RevertEmailChange reverts a pending or already-confirmed email change
// using the token mailed to the original address by RequestEmailChange.
func (s *Service) RevertEmailChange(ctx context.Context, token string) error {
	tenantID := domain.TenantIDFromContext(ctx)

	user, err := s.users.ConsumeEmailRevertToken(ctx, tenantID, token)
	if err != nil {
		switch {
		case errors.Is(err, storage.ErrNotFound):
			return fmt.Errorf("email revert token: %w", api.ErrNotFound)
		case errors.Is(err, storage.ErrTokenExpired):
			return fmt.Errorf("email revert token expired: %w", api.ErrGone)
		case errors.Is(err, storage.ErrDuplicateEmail):
			return fmt.Errorf("previous email already in use: %w", api.ErrConflict)
		default:
			return fmt.Errorf("revert email change: %w", err)
		}
	}

	if err := s.tokens.RevokeAllForUser(ctx, tenantID, user.ID); err != nil {
		s.logger.Error("failed to revoke sessions after email revert", zap.String("user_id", user.ID), zap.Error(err))
	}

	s.audit.LogEvent(ctx, audit.Event{
		Type:     audit.EventEmailChangeReverted,
		ActorID:  user.ID,
		TargetID: user.ID,
		Metadata: map[string]string{"email": user.Email},
	})

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
