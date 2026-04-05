package mocks

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/domain"
)

// MockConsentSessionRepository is a configurable mock for storage.ConsentSessionRepository.
type MockConsentSessionRepository struct {
	CreateFn             func(ctx context.Context, session *domain.ConsentSession) (*domain.ConsentSession, error)
	FindByChallengeFn    func(ctx context.Context, challenge string) (*domain.ConsentSession, error)
	FindByVerifierFn     func(ctx context.Context, verifier string) (*domain.ConsentSession, error)
	UpdateStateFn        func(ctx context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error
	FindByUserAndClientFn func(ctx context.Context, userID string, clientID uuid.UUID) ([]*domain.ConsentSession, error)
	RevokeFn             func(ctx context.Context, userID string, clientID uuid.UUID) (int64, error)
	DeleteExpiredFn      func(ctx context.Context, before time.Time) (int64, error)
}

// Create delegates to CreateFn.
func (m *MockConsentSessionRepository) Create(ctx context.Context, session *domain.ConsentSession) (*domain.ConsentSession, error) {
	return m.CreateFn(ctx, session)
}

// FindByChallenge delegates to FindByChallengeFn.
func (m *MockConsentSessionRepository) FindByChallenge(ctx context.Context, challenge string) (*domain.ConsentSession, error) {
	return m.FindByChallengeFn(ctx, challenge)
}

// FindByVerifier delegates to FindByVerifierFn.
func (m *MockConsentSessionRepository) FindByVerifier(ctx context.Context, verifier string) (*domain.ConsentSession, error) {
	return m.FindByVerifierFn(ctx, verifier)
}

// UpdateState delegates to UpdateStateFn.
func (m *MockConsentSessionRepository) UpdateState(ctx context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error {
	return m.UpdateStateFn(ctx, id, state, grantedScopes)
}

// FindByUserAndClient delegates to FindByUserAndClientFn.
func (m *MockConsentSessionRepository) FindByUserAndClient(ctx context.Context, userID string, clientID uuid.UUID) ([]*domain.ConsentSession, error) {
	return m.FindByUserAndClientFn(ctx, userID, clientID)
}

// Revoke delegates to RevokeFn.
func (m *MockConsentSessionRepository) Revoke(ctx context.Context, userID string, clientID uuid.UUID) (int64, error) {
	return m.RevokeFn(ctx, userID, clientID)
}

// DeleteExpired delegates to DeleteExpiredFn.
func (m *MockConsentSessionRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	return m.DeleteExpiredFn(ctx, before)
}
