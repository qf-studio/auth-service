package session

import (
	"context"
	"fmt"
	"sync"

	"github.com/qf-studio/auth-service/internal/api"
)

// MemoryStore is an in-memory implementation of Store, used only by
// tests. It is per-process, so production must use RedisStore.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string][]api.SessionInfo // keyed by userID
}

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string][]api.SessionInfo),
	}
}

// Create stores a new session.
func (m *MemoryStore) Create(_ context.Context, s *api.SessionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[s.UserID] = append(m.sessions[s.UserID], *s)
	return nil
}

// ListByUser returns all sessions for the given user.
func (m *MemoryStore) ListByUser(_ context.Context, userID string) ([]api.SessionInfo, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.sessions[userID]
	if sessions == nil {
		return []api.SessionInfo{}, nil
	}
	result := make([]api.SessionInfo, len(sessions))
	copy(result, sessions)
	return result, nil
}

// Delete removes a specific session for the given user.
func (m *MemoryStore) Delete(_ context.Context, userID, sessionID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	sessions := m.sessions[userID]
	for i, s := range sessions {
		if s.ID == sessionID {
			m.sessions[userID] = append(sessions[:i], sessions[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("session not found: %w", api.ErrNotFound)
}

// DeleteAllForUser removes all sessions for the given user.
func (m *MemoryStore) DeleteAllForUser(_ context.Context, userID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, userID)
	return nil
}
