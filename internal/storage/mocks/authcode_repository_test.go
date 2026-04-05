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

// ── MockAuthorizationCodeRepository Tests ─────────────────────────────────────

func TestMockAuthCodeRepo_Create(t *testing.T) {
	codeID := uuid.New()
	clientID := uuid.New()

	repo := &mocks.MockAuthorizationCodeRepository{
		CreateFn: func(_ context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error) {
			code.ID = codeID
			code.CreatedAt = time.Now().UTC()
			return code, nil
		},
	}

	code := &domain.AuthorizationCode{
		CodeHash:            "sha256_test_hash",
		ClientID:            clientID,
		UserID:              "user-create",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid", "profile"},
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-123",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	}

	result, err := repo.Create(context.Background(), code)
	require.NoError(t, err)
	assert.Equal(t, codeID, result.ID)
	assert.Equal(t, "sha256_test_hash", result.CodeHash)
	assert.Equal(t, clientID, result.ClientID)
	assert.Equal(t, "S256", result.CodeChallengeMethod)
	assert.NotZero(t, result.CreatedAt)
}

func TestMockAuthCodeRepo_Create_DuplicateError(t *testing.T) {
	errDuplicate := errors.New("duplicate authorization code")
	repo := &mocks.MockAuthorizationCodeRepository{
		CreateFn: func(_ context.Context, _ *domain.AuthorizationCode) (*domain.AuthorizationCode, error) {
			return nil, errDuplicate
		},
	}

	_, err := repo.Create(context.Background(), &domain.AuthorizationCode{})
	assert.ErrorIs(t, err, errDuplicate)
}

func TestMockAuthCodeRepo_FindByCodeHash(t *testing.T) {
	expected := &domain.AuthorizationCode{
		ID:                  uuid.New(),
		CodeHash:            "sha256_lookup_hash",
		ClientID:            uuid.New(),
		UserID:              "user-find",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       "challenge-value",
		CodeChallengeMethod: "S256",
		Nonce:               "nonce-find",
		ExpiresAt:           time.Now().Add(5 * time.Minute),
		CreatedAt:           time.Now(),
	}

	repo := &mocks.MockAuthorizationCodeRepository{
		FindByCodeHashFn: func(_ context.Context, codeHash string) (*domain.AuthorizationCode, error) {
			if codeHash == "sha256_lookup_hash" {
				return expected, nil
			}
			return nil, errors.New("not found")
		},
	}

	// Found.
	result, err := repo.FindByCodeHash(context.Background(), "sha256_lookup_hash")
	require.NoError(t, err)
	assert.Equal(t, expected.ID, result.ID)
	assert.Equal(t, "sha256_lookup_hash", result.CodeHash)
	assert.Equal(t, "S256", result.CodeChallengeMethod)

	// Not found.
	_, err = repo.FindByCodeHash(context.Background(), "nonexistent_hash")
	assert.Error(t, err)
}

func TestMockAuthCodeRepo_MarkUsed(t *testing.T) {
	usedIDs := make(map[uuid.UUID]bool)

	repo := &mocks.MockAuthorizationCodeRepository{
		MarkUsedFn: func(_ context.Context, id uuid.UUID) error {
			if usedIDs[id] {
				return errors.New("authorization code already used")
			}
			usedIDs[id] = true
			return nil
		},
	}

	codeID := uuid.New()

	// First use succeeds.
	err := repo.MarkUsed(context.Background(), codeID)
	require.NoError(t, err)

	// Second use fails (replay protection).
	err = repo.MarkUsed(context.Background(), codeID)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already used")
}

func TestMockAuthCodeRepo_MarkUsed_NotFound(t *testing.T) {
	errNotFound := errors.New("not found")
	repo := &mocks.MockAuthorizationCodeRepository{
		MarkUsedFn: func(_ context.Context, _ uuid.UUID) error {
			return errNotFound
		},
	}

	err := repo.MarkUsed(context.Background(), uuid.New())
	assert.ErrorIs(t, err, errNotFound)
}

func TestMockAuthCodeRepo_DeleteExpired(t *testing.T) {
	repo := &mocks.MockAuthorizationCodeRepository{
		DeleteExpiredFn: func(_ context.Context, before time.Time) (int64, error) {
			// Simulate 3 expired codes cleaned up.
			return 3, nil
		},
	}

	count, err := repo.DeleteExpired(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(3), count)
}

func TestMockAuthCodeRepo_DeleteExpired_NoExpired(t *testing.T) {
	repo := &mocks.MockAuthorizationCodeRepository{
		DeleteExpiredFn: func(_ context.Context, _ time.Time) (int64, error) {
			return 0, nil
		},
	}

	count, err := repo.DeleteExpired(context.Background(), time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(0), count)
}

// ── Full PKCE lifecycle via mock ──────────────────────────────────────────────

func TestMockAuthCodeRepo_PKCELifecycle(t *testing.T) {
	store := make(map[string]*domain.AuthorizationCode)

	repo := &mocks.MockAuthorizationCodeRepository{
		CreateFn: func(_ context.Context, code *domain.AuthorizationCode) (*domain.AuthorizationCode, error) {
			if _, exists := store[code.CodeHash]; exists {
				return nil, errors.New("duplicate")
			}
			code.ID = uuid.New()
			code.CreatedAt = time.Now().UTC()
			store[code.CodeHash] = code
			return code, nil
		},
		FindByCodeHashFn: func(_ context.Context, hash string) (*domain.AuthorizationCode, error) {
			if c, ok := store[hash]; ok {
				return c, nil
			}
			return nil, errors.New("not found")
		},
		MarkUsedFn: func(_ context.Context, id uuid.UUID) error {
			for _, c := range store {
				if c.ID == id {
					if c.UsedAt != nil {
						return errors.New("already used")
					}
					now := time.Now()
					c.UsedAt = &now
					return nil
				}
			}
			return errors.New("not found")
		},
	}

	// Step 1: Create code with PKCE.
	code, err := repo.Create(context.Background(), &domain.AuthorizationCode{
		CodeHash:            "pkce_hash_lifecycle",
		ClientID:            uuid.New(),
		UserID:              "user-pkce-lifecycle",
		RedirectURI:         "https://app.example.com/cb",
		Scopes:              []string{"openid"},
		CodeChallenge:       "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
		CodeChallengeMethod: "S256",
		ExpiresAt:           time.Now().Add(10 * time.Minute),
	})
	require.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, code.ID)

	// Step 2: Look up by hash.
	found, err := repo.FindByCodeHash(context.Background(), "pkce_hash_lifecycle")
	require.NoError(t, err)
	assert.Equal(t, code.ID, found.ID)
	assert.Equal(t, "S256", found.CodeChallengeMethod)
	assert.Equal(t, "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk", found.CodeChallenge)
	assert.False(t, found.IsUsed())

	// Step 3: Mark used.
	err = repo.MarkUsed(context.Background(), found.ID)
	require.NoError(t, err)

	// Step 4: Verify it's marked used.
	used, err := repo.FindByCodeHash(context.Background(), "pkce_hash_lifecycle")
	require.NoError(t, err)
	assert.True(t, used.IsUsed())

	// Step 5: Cannot reuse.
	err = repo.MarkUsed(context.Background(), found.ID)
	assert.Error(t, err)
}
