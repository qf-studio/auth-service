// Package session provides session management including creation,
// listing, and revocation of user sessions.
package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
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
