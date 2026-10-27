package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/qf-studio/auth-service/internal/api"
)

const (
	// sessionKeyPrefix namespaces every key written by RedisStore.
	sessionKeyPrefix = "session:"
)

// RedisStore is a Redis-backed Store shared by every service instance.
//
// Layout per user:
//
//	session:{userID}:idx       sorted set of session IDs scored by expiry (unix seconds)
//	session:{userID}:s:{id}    JSON-encoded api.SessionInfo, with its own TTL
//
// Each session carries its own TTL (the refresh-token lifetime), so a session
// disappears when the refresh token it belongs to can no longer be used. The
// index lets ListByUser and DeleteAllForUser enumerate a user's sessions
// without SCAN.
type RedisStore struct {
	client redis.Cmdable
	ttl    time.Duration
}

// NewRedisStore creates a RedisStore whose sessions expire after ttl
// (set it to the refresh-token TTL).
func NewRedisStore(client redis.Cmdable, ttl time.Duration) *RedisStore {
	return &RedisStore{client: client, ttl: ttl}
}

func indexKey(userID string) string { return sessionKeyPrefix + userID + ":idx" }

func sessionKey(userID, sessionID string) string {
	return sessionKeyPrefix + userID + ":s:" + sessionID
}

// Create stores a new session.
func (r *RedisStore) Create(ctx context.Context, s *api.SessionInfo) error {
	data, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("marshal session: %w", err)
	}

	expiry := time.Now().Add(r.ttl)
	pipe := r.client.TxPipeline()
	pipe.Set(ctx, sessionKey(s.UserID, s.ID), data, r.ttl)
	pipe.ZAdd(ctx, indexKey(s.UserID), redis.Z{Score: float64(expiry.Unix()), Member: s.ID})
	// The newest session always expires last, so the index lives that long.
	pipe.Expire(ctx, indexKey(s.UserID), r.ttl)
	if _, err := pipe.Exec(ctx); err != nil {
		return fmt.Errorf("store session: %w", err)
	}
	return nil
}

// ListByUser returns the user's unexpired sessions, oldest first.
func (r *RedisStore) ListByUser(ctx context.Context, userID string) ([]api.SessionInfo, error) {
	idx := indexKey(userID)
	now := strconv.FormatInt(time.Now().Unix(), 10)

	// Drop index entries whose session has expired.
	if err := r.client.ZRemRangeByScore(ctx, idx, "-inf", "("+now).Err(); err != nil {
		return nil, fmt.Errorf("prune session index: %w", err)
	}
	ids, err := r.client.ZRange(ctx, idx, 0, -1).Result()
	if err != nil {
		return nil, fmt.Errorf("read session index: %w", err)
	}

	sessions := make([]api.SessionInfo, 0, len(ids))
	if len(ids) == 0 {
		return sessions, nil
	}

	keys := make([]string, len(ids))
	for i, id := range ids {
		keys[i] = sessionKey(userID, id)
	}
	vals, err := r.client.MGet(ctx, keys...).Result()
	if err != nil {
		return nil, fmt.Errorf("read sessions: %w", err)
	}

	var stale []interface{}
	for i, v := range vals {
		str, ok := v.(string)
		if !ok { // expired or deleted between index read and fetch
			stale = append(stale, ids[i])
			continue
		}
		var info api.SessionInfo
		if err := json.Unmarshal([]byte(str), &info); err != nil {
			return nil, fmt.Errorf("decode session %s: %w", ids[i], err)
		}
		sessions = append(sessions, info)
	}
	if len(stale) > 0 {
		// Best-effort index cleanup; stale members are skipped on read anyway.
		_ = r.client.ZRem(ctx, idx, stale...).Err()
	}

	sort.Slice(sessions, func(a, b int) bool { return sessions[a].CreatedAt.Before(sessions[b].CreatedAt) })
	return sessions, nil
}

// Delete removes a specific session for the given user.
func (r *RedisStore) Delete(ctx context.Context, userID, sessionID string) error {
	pipe := r.client.TxPipeline()
	del := pipe.Del(ctx, sessionKey(userID, sessionID))
	pipe.ZRem(ctx, indexKey(userID), sessionID)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, redis.Nil) {
		return fmt.Errorf("delete session: %w", err)
	}
	if del.Val() == 0 {
		return fmt.Errorf("session not found: %w", api.ErrNotFound)
	}
	return nil
}

// DeleteAllForUser removes every session for the given user.
func (r *RedisStore) DeleteAllForUser(ctx context.Context, userID string) error {
	idx := indexKey(userID)
	ids, err := r.client.ZRange(ctx, idx, 0, -1).Result()
	if err != nil {
		return fmt.Errorf("read session index: %w", err)
	}

	keys := make([]string, 0, len(ids)+1)
	for _, id := range ids {
		keys = append(keys, sessionKey(userID, id))
	}
	keys = append(keys, idx)
	if err := r.client.Del(ctx, keys...).Err(); err != nil {
		return fmt.Errorf("delete sessions: %w", err)
	}
	return nil
}
