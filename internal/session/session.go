// Package session provides session management including creation,
// listing, and revocation of user sessions.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"github.com/qf-studio/auth-service/internal/api"
)

const sessionIDBytes = 16

// Store defines the storage operations for session persistence.
type Store interface {
	Create(ctx context.Context, s *api.SessionInfo) error
	ListByUser(ctx context.Context, userID string) ([]api.SessionInfo, error)
	Delete(ctx context.Context, userID, sessionID string) error
	DeleteAllForUser(ctx context.Context, userID string) error
}

// Service implements api.SessionService backed by a Store.
type Service struct {
	store Store
}

// NewService creates a new session Service.
func NewService(store Store) *Service {
	return &Service{store: store}
}

// CreateSession creates a new session record for the given user.
func (s *Service) CreateSession(ctx context.Context, userID, ipAddress, userAgent string) (*api.SessionInfo, error) {
	id, err := generateSessionID()
	if err != nil {
		return nil, fmt.Errorf("generate session id: %w", err)
	}

	now := time.Now().UTC()
	info := &api.SessionInfo{
		ID:             id,
		UserID:         userID,
		IPAddress:      ipAddress,
		UserAgent:      userAgent,
		CreatedAt:      now,
		LastActivityAt: now,
	}

	if err := s.store.Create(ctx, info); err != nil {
		return nil, fmt.Errorf("create session: %w", err)
	}

	return info, nil
}

// ListSessions returns all active sessions for the given user.
func (s *Service) ListSessions(ctx context.Context, userID string) ([]api.SessionInfo, error) {
	sessions, err := s.store.ListByUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return sessions, nil
}

// DeleteSession removes a specific session for the given user.
func (s *Service) DeleteSession(ctx context.Context, userID, sessionID string) error {
	if err := s.store.Delete(ctx, userID, sessionID); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}
	return nil
}

// DeleteAllSessions removes all sessions for the given user.
func (s *Service) DeleteAllSessions(ctx context.Context, userID string) error {
	if err := s.store.DeleteAllForUser(ctx, userID); err != nil {
		return fmt.Errorf("delete all sessions: %w", err)
	}
	return nil
}

// generateSessionID produces a cryptographically random hex-encoded session ID.
func generateSessionID() (string, error) {
	b := make([]byte, sessionIDBytes)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("crypto/rand: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// MemoryStore is an in-memory implementation of Store, suitable for
// development and testing. Production should use a Redis or PostgreSQL store.
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
