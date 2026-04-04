// Package session provides session management backed by Redis.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

const (
	// sessKeyPrefix is the Redis key prefix for individual session data.
	sessKeyPrefix = "sess:"

	// userSessKeyPrefix is the Redis key prefix for the set of session IDs per user.
	userSessKeyPrefix = "user_sess:"

	// defaultSessionTTL is the maximum lifetime of a session (24 hours).
	defaultSessionTTL = 24 * time.Hour
)

// SessionService defines the session management operations.
type SessionService interface {
	CreateSession(ctx context.Context, session *domain.Session) (*domain.Session, error)
	GetSession(ctx context.Context, sessionID string) (*domain.Session, error)
	ListSessions(ctx context.Context, userID string) ([]*domain.Session, error)
	UpdateActivity(ctx context.Context, sessionID string) error
	RevokeSession(ctx context.Context, userID, sessionID string) error
	RevokeAllSessions(ctx context.Context, userID string) error
}

// Service implements SessionService using Redis as the backing store.
type Service struct {
	redis  *redis.Client
	logger *zap.Logger
}

// NewService creates a new session Service.
func NewService(redisClient *redis.Client, logger *zap.Logger) *Service {
	return &Service{
		redis:  redisClient,
		logger: logger,
	}
}

// CreateSession stores a new session in Redis with a 24h TTL.
// It generates a session ID if one is not set.
func (s *Service) CreateSession(ctx context.Context, session *domain.Session) (*domain.Session, error) {
	if session.ID == "" {
		session.ID = uuid.NewString()
	}

	now := time.Now()
	session.CreatedAt = now
	session.LastActivityAt = now

	data, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("marshal session: %w", err)
	}

	sessKey := sessKeyPrefix + session.ID
	userKey := userSessKeyPrefix + session.UserID

	pipe := s.redis.Pipeline()
	pipe.Set(ctx, sessKey, data, defaultSessionTTL)
	pipe.SAdd(ctx, userKey, session.ID)
	pipe.Expire(ctx, userKey, defaultSessionTTL)
	if _, err := pipe.Exec(ctx); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	s.logger.Info("session created",
		zap.String("session_id", session.ID),
		zap.String("user_id", session.UserID),
	)

	return session, nil
}

// GetSession retrieves a session by ID from Redis.
func (s *Service) GetSession(ctx context.Context, sessionID string) (*domain.Session, error) {
	sessKey := sessKeyPrefix + sessionID

	data, err := s.redis.Get(ctx, sessKey).Bytes()
	if err == redis.Nil {
		return nil, domain.ErrSessionNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("get session: %w", err)
	}

	var session domain.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, fmt.Errorf("unmarshal session: %w", err)
	}

	return &session, nil
}

// ListSessions returns all active sessions for a user.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]*domain.Session, error) {
	userKey := userSessKeyPrefix + userID

	sessionIDs, err := s.redis.SMembers(ctx, userKey).Result()
	if err != nil {
		return nil, fmt.Errorf("list session IDs: %w", err)
	}

	if len(sessionIDs) == 0 {
		return []*domain.Session{}, nil
	}

	// Build keys for MGET.
	keys := make([]string, len(sessionIDs))
	for i, id := range sessionIDs {
		keys[i] = sessKeyPrefix + id
	}

	values, err := s.redis.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("get sessions: %w", err)
	}

	// Collect valid sessions and clean up expired references.
	sessions := make([]*domain.Session, 0, len(values))
	var expired []string
	for i, val := range values {
		if val == nil {
			// Session key expired but still in the user set.
			expired = append(expired, sessionIDs[i])
			continue
		}

		str, ok := val.(string)
		if !ok {
			continue
		}

		var sess domain.Session
		if err := json.Unmarshal([]byte(str), &sess); err != nil {
			s.logger.Warn("failed to unmarshal session", zap.String("session_id", sessionIDs[i]), zap.Error(err))
			continue
		}
		sessions = append(sessions, &sess)
	}

	// Clean up stale references from the user set.
	if len(expired) > 0 {
		members := make([]interface{}, len(expired))
		for i, id := range expired {
			members[i] = id
		}
		if err := s.redis.SRem(ctx, userKey, members...).Err(); err != nil {
			s.logger.Warn("failed to clean expired session refs", zap.Error(err))
		}
	}

	return sessions, nil
}

// UpdateActivity refreshes the last activity timestamp and resets the TTL.
func (s *Service) UpdateActivity(ctx context.Context, sessionID string) error {
	sessKey := sessKeyPrefix + sessionID

	data, err := s.redis.Get(ctx, sessKey).Bytes()
	if err == redis.Nil {
		return domain.ErrSessionNotFound
	}
	if err != nil {
		return fmt.Errorf("get session for update: %w", err)
	}

	var session domain.Session
	if err := json.Unmarshal(data, &session); err != nil {
		return fmt.Errorf("unmarshal session: %w", err)
	}

	session.LastActivityAt = time.Now()

	updated, err := json.Marshal(&session)
	if err != nil {
		return fmt.Errorf("marshal updated session: %w", err)
	}

	if err := s.redis.Set(ctx, sessKey, updated, defaultSessionTTL).Err(); err != nil {
		return fmt.Errorf("update session activity: %w", err)
	}

	return nil
}

// RevokeSession removes a single session for a user.
func (s *Service) RevokeSession(ctx context.Context, userID, sessionID string) error {
	sessKey := sessKeyPrefix + sessionID
	userKey := userSessKeyPrefix + userID

	pipe := s.redis.Pipeline()
	pipe.Del(ctx, sessKey)
	pipe.SRem(ctx, userKey, sessionID)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("revoke session: %w", err)
	}

	s.logger.Info("session revoked",
		zap.String("session_id", sessionID),
		zap.String("user_id", userID),
	)

	return nil
}

// RevokeAllSessions removes all sessions for a user.
func (s *Service) RevokeAllSessions(ctx context.Context, userID string) error {
	userKey := userSessKeyPrefix + userID

	sessionIDs, err := s.redis.SMembers(ctx, userKey).Result()
	if err != nil {
		return fmt.Errorf("list sessions for revocation: %w", err)
	}

	if len(sessionIDs) == 0 {
		return nil
	}

	// Delete all session keys + the user set in one pipeline.
	keys := make([]string, 0, len(sessionIDs)+1)
	for _, id := range sessionIDs {
		keys = append(keys, sessKeyPrefix+id)
	}
	keys = append(keys, userKey)

	if err := s.redis.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("revoke all sessions: %w", err)
	}

	s.logger.Info("all sessions revoked",
		zap.String("user_id", userID),
		zap.Int("count", len(sessionIDs)),
	)

	return nil
}

// Ensure Service implements SessionService at compile time.
var _ SessionService = (*Service)(nil)
