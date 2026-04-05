package mocks_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

// ── MockConsentSessionRepository Tests ────────────────────────────────────────

func TestMockConsentRepo_Create(t *testing.T) {
	sessionID := uuid.New()

	repo := &mocks.MockConsentSessionRepository{
		CreateFn: func(_ context.Context, session *domain.ConsentSession) (*domain.ConsentSession, error) {
			session.ID = sessionID
			session.CreatedAt = time.Now().UTC()
			session.UpdatedAt = session.CreatedAt
			return session, nil
		},
	}

	session := &domain.ConsentSession{
		Challenge:       "chal-create",
		Verifier:        "veri-create",
		ClientID:        uuid.New(),
		UserID:          "user-consent-create",
		RequestedScopes: []string{"openid", "profile", "email"},
		State:           domain.ConsentStatePending,
		LoginSessionID:  "login-sess-1",
	}

	result, err := repo.Create(context.Background(), session)
	require.NoError(t, err)
	assert.Equal(t, sessionID, result.ID)
	assert.Equal(t, "chal-create", result.Challenge)
	assert.Equal(t, domain.ConsentStatePending, result.State)
	assert.NotZero(t, result.CreatedAt)
}

func TestMockConsentRepo_Create_DuplicateChallenge(t *testing.T) {
	errDuplicate := errors.New("duplicate consent session")
	repo := &mocks.MockConsentSessionRepository{
		CreateFn: func(_ context.Context, _ *domain.ConsentSession) (*domain.ConsentSession, error) {
			return nil, errDuplicate
		},
	}

	_, err := repo.Create(context.Background(), &domain.ConsentSession{})
	assert.ErrorIs(t, err, errDuplicate)
}

func TestMockConsentRepo_FindByChallenge(t *testing.T) {
	expected := &domain.ConsentSession{
		ID:              uuid.New(),
		Challenge:       "chal-find",
		Verifier:        "veri-find",
		ClientID:        uuid.New(),
		UserID:          "user-find",
		RequestedScopes: []string{"openid"},
		State:           domain.ConsentStatePending,
	}

	repo := &mocks.MockConsentSessionRepository{
		FindByChallengeFn: func(_ context.Context, challenge string) (*domain.ConsentSession, error) {
			if challenge == "chal-find" {
				return expected, nil
			}
			return nil, errors.New("not found")
		},
	}

	result, err := repo.FindByChallenge(context.Background(), "chal-find")
	require.NoError(t, err)
	assert.Equal(t, expected.ID, result.ID)
	assert.Equal(t, "chal-find", result.Challenge)

	_, err = repo.FindByChallenge(context.Background(), "nonexistent")
	assert.Error(t, err)
}

func TestMockConsentRepo_FindByVerifier(t *testing.T) {
	expected := &domain.ConsentSession{
		ID:       uuid.New(),
		Verifier: "veri-lookup",
		State:    domain.ConsentStateAccepted,
	}

	repo := &mocks.MockConsentSessionRepository{
		FindByVerifierFn: func(_ context.Context, verifier string) (*domain.ConsentSession, error) {
			if verifier == "veri-lookup" {
				return expected, nil
			}
			return nil, errors.New("not found")
		},
	}

	result, err := repo.FindByVerifier(context.Background(), "veri-lookup")
	require.NoError(t, err)
	assert.Equal(t, expected.ID, result.ID)
	assert.Equal(t, domain.ConsentStateAccepted, result.State)

	_, err = repo.FindByVerifier(context.Background(), "bad-verifier")
	assert.Error(t, err)
}

func TestMockConsentRepo_UpdateState(t *testing.T) {
	var updatedState domain.ConsentState
	var updatedScopes []string

	sessionID := uuid.New()
	repo := &mocks.MockConsentSessionRepository{
		UpdateStateFn: func(_ context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error {
			if id != sessionID {
				return errors.New("not found")
			}
			updatedState = state
			updatedScopes = grantedScopes
			return nil
		},
	}

	// Accept consent.
	err := repo.UpdateState(context.Background(), sessionID, domain.ConsentStateAccepted, []string{"openid", "profile"})
	require.NoError(t, err)
	assert.Equal(t, domain.ConsentStateAccepted, updatedState)
	assert.Equal(t, []string{"openid", "profile"}, updatedScopes)

	// Not found.
	err = repo.UpdateState(context.Background(), uuid.New(), domain.ConsentStateRejected, nil)
	assert.Error(t, err)
}

func TestMockConsentRepo_FindByUserAndClient(t *testing.T) {
	clientID := uuid.New()
	sessions := []*domain.ConsentSession{
		{
			ID:       uuid.New(),
			ClientID: clientID,
			UserID:   "user-multi",
			State:    domain.ConsentStateAccepted,
		},
		{
			ID:       uuid.New(),
			ClientID: clientID,
			UserID:   "user-multi",
			State:    domain.ConsentStateAccepted,
		},
	}

	repo := &mocks.MockConsentSessionRepository{
		FindByUserAndClientFn: func(_ context.Context, userID string, cID uuid.UUID) ([]*domain.ConsentSession, error) {
			if userID == "user-multi" && cID == clientID {
				return sessions, nil
			}
			return nil, nil
		},
	}

	result, err := repo.FindByUserAndClient(context.Background(), "user-multi", clientID)
	require.NoError(t, err)
	assert.Len(t, result, 2)

	empty, err := repo.FindByUserAndClient(context.Background(), "other-user", clientID)
	require.NoError(t, err)
	assert.Nil(t, empty)
}

func TestMockConsentRepo_Revoke(t *testing.T) {
	clientID := uuid.New()

	repo := &mocks.MockConsentSessionRepository{
		RevokeFn: func(_ context.Context, userID string, cID uuid.UUID) (int64, error) {
			if userID == "user-revoke" && cID == clientID {
				return 2, nil // 2 sessions revoked.
			}
			return 0, nil
		},
	}

	count, err := repo.Revoke(context.Background(), "user-revoke", clientID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), count)

	count, err = repo.Revoke(context.Background(), "no-sessions", clientID)
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

func TestMockConsentRepo_DeleteExpired(t *testing.T) {
	repo := &mocks.MockConsentSessionRepository{
		DeleteExpiredFn: func(_ context.Context, _ time.Time) (int64, error) {
			return 5, nil
		},
	}

	count, err := repo.DeleteExpired(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(5), count)
}

// ── Full Consent Lifecycle via mock ───────────────────────────────────────────

func TestMockConsentRepo_FullLifecycle(t *testing.T) {
	store := make(map[string]*domain.ConsentSession)

	repo := &mocks.MockConsentSessionRepository{
		CreateFn: func(_ context.Context, s *domain.ConsentSession) (*domain.ConsentSession, error) {
			if _, exists := store[s.Challenge]; exists {
				return nil, errors.New("duplicate")
			}
			s.ID = uuid.New()
			now := time.Now().UTC()
			s.CreatedAt = now
			s.UpdatedAt = now
			store[s.Challenge] = s
			return s, nil
		},
		FindByChallengeFn: func(_ context.Context, challenge string) (*domain.ConsentSession, error) {
			if s, ok := store[challenge]; ok {
				return s, nil
			}
			return nil, errors.New("not found")
		},
		FindByVerifierFn: func(_ context.Context, verifier string) (*domain.ConsentSession, error) {
			for _, s := range store {
				if s.Verifier == verifier {
					return s, nil
				}
			}
			return nil, errors.New("not found")
		},
		UpdateStateFn: func(_ context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error {
			for _, s := range store {
				if s.ID == id {
					s.State = state
					s.GrantedScopes = grantedScopes
					s.UpdatedAt = time.Now().UTC()
					return nil
				}
			}
			return errors.New("not found")
		},
	}

	// Step 1: Create pending consent session.
	session, err := repo.Create(context.Background(), &domain.ConsentSession{
		Challenge:        "lifecycle-challenge",
		Verifier:         "lifecycle-verifier",
		ClientID:         uuid.New(),
		UserID:           "user-lifecycle",
		RequestedScopes:  []string{"openid", "profile", "email"},
		State:            domain.ConsentStatePending,
		LoginSessionID:   "login-1",
		EncryptedPayload: []byte(`{"redirect_uri":"https://app.example.com/cb"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, domain.ConsentStatePending, session.State)
	assert.Empty(t, session.GrantedScopes)

	// Step 2: Look up by challenge (login UI uses this).
	found, err := repo.FindByChallenge(context.Background(), "lifecycle-challenge")
	require.NoError(t, err)
	assert.Equal(t, session.ID, found.ID)
	assert.Equal(t, domain.ConsentStatePending, found.State)

	// Step 3: Accept consent with partial scopes.
	err = repo.UpdateState(context.Background(), session.ID, domain.ConsentStateAccepted, []string{"openid", "profile"})
	require.NoError(t, err)

	// Step 4: Verify state changed.
	accepted, err := repo.FindByChallenge(context.Background(), "lifecycle-challenge")
	require.NoError(t, err)
	assert.Equal(t, domain.ConsentStateAccepted, accepted.State)
	assert.Equal(t, []string{"openid", "profile"}, accepted.GrantedScopes)

	// Step 5: Look up by verifier (token endpoint uses this).
	byVerifier, err := repo.FindByVerifier(context.Background(), "lifecycle-verifier")
	require.NoError(t, err)
	assert.Equal(t, session.ID, byVerifier.ID)
	assert.Equal(t, domain.ConsentStateAccepted, byVerifier.State)

	// Step 6: Verify encrypted payload survived.
	assert.Equal(t, []byte(`{"redirect_uri":"https://app.example.com/cb"}`), byVerifier.EncryptedPayload)
}
