// Package hibp — scanner.go implements a background breach scanner that
// periodically re-checks cached password hashes against the HIBP API.
//
// Design: Argon2id hashes cannot be reversed, so we cannot check them against
// HIBP directly. Instead, the auth service caches the SHA-1 hash of each
// user's password in Redis at login time (capture-on-login pattern). The
// scanner reads these cached hashes and queries HIBP to detect newly breached
// passwords. When a breach is detected, the user is flagged with
// force_password_change and an audit event is emitted.
package hibp

import (
	"context"
	"crypto/sha1" //#nosec G505 — SHA-1 required by HIBP API protocol
	"fmt"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/storage"
)

const (
	// sha1CachePrefix is the Redis key prefix for cached password SHA-1 hashes.
	// Keys: hibp_sha1:<user_id> → uppercase hex SHA-1 of the password.
	sha1CachePrefix = "hibp_sha1:"

	// sha1CacheTTL is how long a cached SHA-1 lives in Redis. The scanner must
	// run at least once within this window to catch the hash before it expires.
	sha1CacheTTL = 30 * 24 * time.Hour // 30 days

	// scanPageSize is the number of user IDs fetched per database page.
	scanPageSize = 100
)

// Scanner periodically checks cached password SHA-1 hashes against the HIBP
// API and flags compromised users.
type Scanner struct {
	checker  BreachChecker
	users    storage.UserRepository
	redis    *redis.Client
	logger   *zap.Logger
	auditor  audit.EventLogger
	interval time.Duration
	done     chan struct{}
}

// NewScanner creates a background breach scanner.
func NewScanner(
	checker BreachChecker,
	users storage.UserRepository,
	redisClient *redis.Client,
	logger *zap.Logger,
	auditor audit.EventLogger,
	interval time.Duration,
) *Scanner {
	return &Scanner{
		checker:  checker,
		users:    users,
		redis:    redisClient,
		logger:   logger,
		auditor:  auditor,
		interval: interval,
		done:     make(chan struct{}),
	}
}

// CachePasswordHash stores the SHA-1 hash of a password in Redis for later
// background scanning. Called at login time when we have the plaintext.
func CachePasswordHash(ctx context.Context, redisClient *redis.Client, userID, password string) error {
	hash := fmt.Sprintf("%X", sha1.Sum([]byte(password))) //#nosec G401
	key := sha1CachePrefix + userID
	return redisClient.Set(ctx, key, hash, sha1CacheTTL).Err()
}

// Start launches the background scanner goroutine. It runs until ctx is cancelled.
func (s *Scanner) Start(ctx context.Context) {
	go s.run(ctx)
}

// Done returns a channel that is closed when the scanner goroutine exits.
func (s *Scanner) Done() <-chan struct{} {
	return s.done
}

func (s *Scanner) run(ctx context.Context) {
	defer close(s.done)

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Run an initial scan shortly after startup.
	s.scan(ctx)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("hibp scanner stopped")
			return
		case <-ticker.C:
			s.scan(ctx)
		}
	}
}

func (s *Scanner) scan(ctx context.Context) {
	s.logger.Info("hibp background scan started")

	var checked, compromised int
	offset := 0

	for {
		userIDs, err := s.users.ListActiveUserIDs(ctx, scanPageSize, offset)
		if err != nil {
			s.logger.Error("hibp scan: list users failed", zap.Error(err))
			return
		}
		if len(userIDs) == 0 {
			break
		}

		for _, userID := range userIDs {
			if ctx.Err() != nil {
				return
			}

			sha1Hash, err := s.redis.Get(ctx, sha1CachePrefix+userID).Result()
			if err == redis.Nil {
				continue // No cached hash for this user.
			}
			if err != nil {
				s.logger.Error("hibp scan: redis get failed", zap.String("user_id", userID), zap.Error(err))
				continue
			}

			breached, err := s.checkSHA1(ctx, sha1Hash)
			if err != nil {
				s.logger.Error("hibp scan: check failed", zap.String("user_id", userID), zap.Error(err))
				continue
			}
			checked++

			if breached {
				compromised++
				s.flagUser(ctx, userID)
			}
		}

		offset += len(userIDs)
		if len(userIDs) < scanPageSize {
			break
		}
	}

	s.logger.Info("hibp background scan completed",
		zap.Int("checked", checked),
		zap.Int("compromised", compromised),
	)
}

// checkSHA1 checks whether the given SHA-1 hash (uppercase hex) appears in
// the HIBP database using the k-anonymity prefix/suffix model.
func (s *Scanner) checkSHA1(ctx context.Context, sha1Hash string) (bool, error) {
	prefix := sha1Hash[:5]
	suffix := sha1Hash[5:]

	// The checker's IsBreached takes a password, but we already have the hash.
	// We need to query the API directly with the prefix.
	client, ok := s.checker.(*Client)
	if !ok {
		// Fallback: can't use this checker for raw hash lookups.
		return false, nil
	}

	body, err := client.fetchRange(ctx, prefix)
	if err != nil {
		return false, err
	}

	return matchesSuffix(strings.NewReader(body), suffix)
}

func (s *Scanner) flagUser(ctx context.Context, userID string) {
	if err := s.users.SetForcePasswordChange(ctx, userID, true); err != nil {
		s.logger.Error("hibp scan: flag user failed", zap.String("user_id", userID), zap.Error(err))
		return
	}

	// Remove the cached hash so we don't re-flag the same user.
	if err := s.redis.Del(ctx, sha1CachePrefix+userID).Err(); err != nil {
		s.logger.Error("hibp scan: delete cache failed", zap.String("user_id", userID), zap.Error(err))
	}

	s.auditor.LogEvent(ctx, audit.Event{
		Type:     audit.EventPasswordCompromised,
		ActorID:  "system",
		TargetID: userID,
		Metadata: map[string]string{"source": "background_scan"},
	})

	s.logger.Warn("user password found in breach",
		zap.String("user_id", userID),
	)
}
