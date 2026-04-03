package client_test

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/client"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// ── Mocks ────────────────────────────────────────────────────────────────────

// mockClientRepo implements storage.ClientRepository for testing.
type mockClientRepo struct {
	createFn          func(ctx context.Context, c *domain.Client) (*domain.Client, error)
	findByIDFn        func(ctx context.Context, id string) (*domain.Client, error)
	listFn            func(ctx context.Context, page, perPage int, includeRevoked bool) ([]*domain.Client, int, error)
	updateFn          func(ctx context.Context, c *domain.Client) (*domain.Client, error)
	deleteFn          func(ctx context.Context, id string) error
	updateLastUsedAtFn func(ctx context.Context, id string, t time.Time) error
}

func (m *mockClientRepo) Create(ctx context.Context, c *domain.Client) (*domain.Client, error) {
	if m.createFn != nil {
		return m.createFn(ctx, c)
	}
	c.CreatedAt = time.Now().UTC()
	c.UpdatedAt = c.CreatedAt
	return c, nil
}

func (m *mockClientRepo) FindByID(ctx context.Context, id string) (*domain.Client, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}

func (m *mockClientRepo) List(ctx context.Context, page, perPage int, includeRevoked bool) ([]*domain.Client, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, page, perPage, includeRevoked)
	}
	return nil, 0, nil
}

func (m *mockClientRepo) Update(ctx context.Context, c *domain.Client) (*domain.Client, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, c)
	}
	c.UpdatedAt = time.Now().UTC()
	return c, nil
}

func (m *mockClientRepo) Delete(ctx context.Context, id string) error {
	if m.deleteFn != nil {
		return m.deleteFn(ctx, id)
	}
	return nil
}

func (m *mockClientRepo) UpdateLastUsedAt(ctx context.Context, id string, t time.Time) error {
	if m.updateLastUsedAtFn != nil {
		return m.updateLastUsedAtFn(ctx, id, t)
	}
	return nil
}

// mockTokenIssuer implements client.TokenIssuer for testing.
type mockTokenIssuer struct {
	issueAccessTokenOnlyFn func(ctx context.Context, subject string, scopes []string, clientType string, ttl time.Duration) (*api.AuthResult, error)
}

func (m *mockTokenIssuer) IssueAccessTokenOnly(ctx context.Context, subject string, scopes []string, clientType string, ttl time.Duration) (*api.AuthResult, error) {
	if m.issueAccessTokenOnlyFn != nil {
		return m.issueAccessTokenOnlyFn(ctx, subject, scopes, clientType, ttl)
	}
	return &api.AuthResult{
		AccessToken:  "qf_at_testtoken",
		RefreshToken: "",
		TokenType:    "Bearer",
		ExpiresIn:    int(ttl.Seconds()),
	}, nil
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func newTestService(repo storage.ClientRepository, issuer client.TokenIssuer) *client.Service {
	return client.NewService(repo, issuer, zap.NewNop())
}

// buildActiveClient creates a domain.Client for use in tests.
// The SecretHash is a real Argon2id hash of "qf_cs_testsecret".
func buildActiveServiceClient(t *testing.T) (*domain.Client, string) {
	t.Helper()
	// We create a client via the service so the hash is correct.
	svc := newTestService(&mockClientRepo{}, &mockTokenIssuer{})
	ctx := context.Background()

	result, err := svc.CreateClient(ctx, &api.CreateClientRequest{
		Name:       "test-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)

	// Return a domain.Client from the repo mock so we can use the real hash.
	// The mock's Create echoes the client back, and CreateClient sets SecretHash.
	c := &domain.Client{
		ID:             uuid.MustParse(result.ID),
		Name:           result.Name,
		ClientType:     domain.ClientTypeService,
		SecretHash:     "", // Will be populated via separate hash call
		Scopes:         result.Scopes,
		Owner:          "",
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      result.CreatedAt,
		UpdatedAt:      result.UpdatedAt,
	}
	return c, result.ClientSecret
}

// ── CreateClient tests ────────────────────────────────────────────────────────

func TestCreateClient_ServiceType(t *testing.T) {
	repo := &mockClientRepo{}
	svc := newTestService(repo, &mockTokenIssuer{})

	result, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "my-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)
	assert.Equal(t, "my-service", result.Name)
	assert.Equal(t, "service", result.ClientType)
	assert.True(t, strings.HasPrefix(result.ClientSecret, "qf_cs_"), "secret must have qf_cs_ prefix")
	assert.NotEmpty(t, result.ID)
}

func TestCreateClient_AgentType(t *testing.T) {
	repo := &mockClientRepo{}
	svc := newTestService(repo, &mockTokenIssuer{})

	result, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "my-agent",
		ClientType: "agent",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)
	assert.Equal(t, "agent", result.ClientType)
	assert.True(t, strings.HasPrefix(result.ClientSecret, "qf_cs_"))
}

func TestCreateClient_SecretNotStoredInPlaintext(t *testing.T) {
	var capturedClient *domain.Client
	repo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedClient = c
			c.CreatedAt = time.Now().UTC()
			c.UpdatedAt = c.CreatedAt
			return c, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	result, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "secure-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)
	require.NotNil(t, capturedClient)

	// The hash stored in DB must not equal the plaintext secret.
	assert.NotEqual(t, result.ClientSecret, capturedClient.SecretHash)
	// The hash should follow PHC format.
	assert.True(t, strings.HasPrefix(capturedClient.SecretHash, "$argon2id$"))
}

func TestCreateClient_DuplicateName(t *testing.T) {
	repo := &mockClientRepo{
		createFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
			return nil, storage.ErrDuplicateClient
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "existing",
		ClientType: "service",
		Scopes:     []string{},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestCreateClient_DefaultTTL_Service(t *testing.T) {
	var capturedClient *domain.Client
	repo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedClient = c
			return c, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "svc",
		ClientType: "service",
		Scopes:     []string{},
	})
	require.NoError(t, err)
	assert.Equal(t, 900, capturedClient.AccessTokenTTL, "service TTL should be 900s (15 min)")
}

func TestCreateClient_DefaultTTL_Agent(t *testing.T) {
	var capturedClient *domain.Client
	repo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedClient = c
			return c, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "agt",
		ClientType: "agent",
		Scopes:     []string{},
	})
	require.NoError(t, err)
	assert.Equal(t, 300, capturedClient.AccessTokenTTL, "agent TTL should be 300s (5 min)")
}

// ── ClientCredentialsGrant tests ──────────────────────────────────────────────

func TestClientCredentialsGrant_Success(t *testing.T) {
	clientID := uuid.New().String()
	// Hash a known secret.
	plainSecret := "qf_cs_testsecretXYZ"
	svc0 := newTestService(&mockClientRepo{}, &mockTokenIssuer{})
	_ = svc0 // used for side-effect check only

	// Build a hash using the service's internal logic by calling CreateClient
	// with a controlled repo that captures the hash.
	var capturedHash string
	capturedClientID := clientID

	// We need a real hash. Create one by calling the service end-to-end.
	setupRepo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedHash = c.SecretHash
			c.ID = uuid.MustParse(capturedClientID)
			c.CreatedAt = time.Now().UTC()
			c.UpdatedAt = c.CreatedAt
			return c, nil
		},
	}
	setupSvc := newTestService(setupRepo, &mockTokenIssuer{})
	result, err := setupSvc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "auth-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)
	plainSecret = result.ClientSecret // use the real generated secret

	// Now test authentication with the captured hash.
	activeClient := &domain.Client{
		ID:             uuid.MustParse(clientID),
		Name:           "auth-service",
		ClientType:     domain.ClientTypeService,
		SecretHash:     capturedHash,
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, id string) (*domain.Client, error) {
			if id == clientID {
				return activeClient, nil
			}
			return nil, storage.ErrNotFound
		},
	}

	var issuedSubject string
	var issuedTTL time.Duration
	issuer := &mockTokenIssuer{
		issueAccessTokenOnlyFn: func(_ context.Context, subject string, _ []string, _ string, ttl time.Duration) (*api.AuthResult, error) {
			issuedSubject = subject
			issuedTTL = ttl
			return &api.AuthResult{
				AccessToken: "qf_at_testtoken",
				TokenType:   "Bearer",
				ExpiresIn:   int(ttl.Seconds()),
			}, nil
		},
	}

	svc := newTestService(repo, issuer)
	authResult, err := svc.ClientCredentialsGrant(context.Background(), clientID, plainSecret)
	require.NoError(t, err)
	assert.Equal(t, "qf_at_testtoken", authResult.AccessToken)
	assert.Empty(t, authResult.RefreshToken, "no refresh token for M2M clients")
	assert.Equal(t, clientID, issuedSubject)
	assert.Equal(t, 900*time.Second, issuedTTL)
}

func TestClientCredentialsGrant_WrongSecret(t *testing.T) {
	clientID := uuid.New().String()
	activeClient := &domain.Client{
		ID:             uuid.MustParse(clientID),
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", // invalid hash
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return activeClient, nil
		},
	}

	svc := newTestService(repo, &mockTokenIssuer{})
	_, err := svc.ClientCredentialsGrant(context.Background(), clientID, "qf_cs_wrongsecret")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestClientCredentialsGrant_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return nil, storage.ErrNotFound
		},
	}

	svc := newTestService(repo, &mockTokenIssuer{})
	_, err := svc.ClientCredentialsGrant(context.Background(), "nonexistent-id", "qf_cs_secret")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestClientCredentialsGrant_Suspended(t *testing.T) {
	clientID := uuid.New().String()

	// Create a real hash for a valid secret.
	var capturedHash string
	setupRepo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedHash = c.SecretHash
			return c, nil
		},
	}
	setupSvc := newTestService(setupRepo, &mockTokenIssuer{})
	result, err := setupSvc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "suspended-client",
		ClientType: "service",
		Scopes:     []string{},
	})
	require.NoError(t, err)

	suspendedClient := &domain.Client{
		ID:             uuid.MustParse(clientID),
		ClientType:     domain.ClientTypeService,
		SecretHash:     capturedHash,
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusSuspended,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return suspendedClient, nil
		},
	}

	svc := newTestService(repo, &mockTokenIssuer{})
	_, err = svc.ClientCredentialsGrant(context.Background(), clientID, result.ClientSecret)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}

func TestClientCredentialsGrant_AgentTTL(t *testing.T) {
	clientID := uuid.New().String()

	var capturedHash string
	setupRepo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedHash = c.SecretHash
			return c, nil
		},
	}
	setupSvc := newTestService(setupRepo, &mockTokenIssuer{})
	result, err := setupSvc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "ai-agent",
		ClientType: "agent",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)

	agentClient := &domain.Client{
		ID:             uuid.MustParse(clientID),
		ClientType:     domain.ClientTypeAgent,
		SecretHash:     capturedHash,
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 300,
		Status:         domain.ClientStatusActive,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return agentClient, nil
		},
	}

	var issuedTTL time.Duration
	issuer := &mockTokenIssuer{
		issueAccessTokenOnlyFn: func(_ context.Context, _ string, _ []string, _ string, ttl time.Duration) (*api.AuthResult, error) {
			issuedTTL = ttl
			return &api.AuthResult{AccessToken: "qf_at_tok", TokenType: "Bearer", ExpiresIn: int(ttl.Seconds())}, nil
		},
	}

	svc := newTestService(repo, issuer)
	_, err = svc.ClientCredentialsGrant(context.Background(), clientID, result.ClientSecret)
	require.NoError(t, err)
	assert.Equal(t, 300*time.Second, issuedTTL, "agent should get 5-min TTL")
}

// ── Admin CRUD tests ──────────────────────────────────────────────────────────

func TestGetClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.GetClient(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestGetClient_Success(t *testing.T) {
	id := uuid.New()
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return &domain.Client{
				ID:         id,
				Name:       "my-svc",
				ClientType: domain.ClientTypeService,
				Scopes:     []string{"read:users"},
				Status:     domain.ClientStatusActive,
				CreatedAt:  time.Now(),
				UpdatedAt:  time.Now(),
			}, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	got, err := svc.GetClient(context.Background(), id.String())
	require.NoError(t, err)
	assert.Equal(t, id.String(), got.ID)
	assert.Equal(t, "my-svc", got.Name)
}

func TestDeleteClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		deleteFn: func(_ context.Context, _ string) error {
			return storage.ErrNotFound
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	err := svc.DeleteClient(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestRotateSecret_ReturnsNewSecret(t *testing.T) {
	id := uuid.New()
	const oldHash = "$argon2id$v=19$m=19456,t=2,p=1$oldhash$oldhashvalue"

	var updatedHash string
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			// Return a fresh copy each call to avoid mutation aliasing.
			return &domain.Client{
				ID:             id,
				Name:           "svc",
				ClientType:     domain.ClientTypeService,
				SecretHash:     oldHash,
				Scopes:         []string{"read:users"},
				AccessTokenTTL: 900,
				Status:         domain.ClientStatusActive,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}, nil
		},
		updateFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			updatedHash = c.SecretHash
			c.UpdatedAt = time.Now().UTC()
			return c, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	result, err := svc.RotateSecret(context.Background(), id.String())
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(result.ClientSecret, "qf_cs_"), "rotated secret must have prefix")
	assert.True(t, strings.HasPrefix(updatedHash, "$argon2id$"), "new hash must be Argon2id PHC format")
	assert.NotEqual(t, oldHash, updatedHash, "hash must change after rotation")
}

func TestUpdateClient_PartialUpdate(t *testing.T) {
	id := uuid.New()
	existing := &domain.Client{
		ID:             id,
		Name:           "old-name",
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$abc$def",
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return existing, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	newName := "new-name"
	got, err := svc.UpdateClient(context.Background(), id.String(), &api.UpdateClientRequest{
		Name: &newName,
	})
	require.NoError(t, err)
	assert.Equal(t, "new-name", got.Name)
}

func TestGetClient_InternalError(t *testing.T) {
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.GetClient(context.Background(), "some-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestDeleteClient_InternalError(t *testing.T) {
	repo := &mockClientRepo{
		deleteFn: func(_ context.Context, _ string) error {
			return fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	err := svc.DeleteClient(context.Background(), "some-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestUpdateClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{} // default returns ErrNotFound
	svc := newTestService(repo, &mockTokenIssuer{})

	name := "new-name"
	_, err := svc.UpdateClient(context.Background(), "nonexistent", &api.UpdateClientRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestUpdateClient_UpdateRepoError(t *testing.T) {
	id := uuid.New()
	existing := &domain.Client{
		ID:             id,
		Name:           "svc",
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$abc$def",
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	tests := []struct {
		name     string
		repoErr  error
		wantErr  error
	}{
		{"duplicate name", storage.ErrDuplicateClient, api.ErrConflict},
		{"not found on update", storage.ErrNotFound, api.ErrNotFound},
		{"internal error", fmt.Errorf("db unavailable"), api.ErrInternalError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			repo := &mockClientRepo{
				findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
					c := *existing
					return &c, nil
				},
				updateFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
					return nil, tc.repoErr
				},
			}
			svc := newTestService(repo, &mockTokenIssuer{})
			newName := "updated"
			_, err := svc.UpdateClient(context.Background(), id.String(), &api.UpdateClientRequest{Name: &newName})
			require.Error(t, err)
			assert.ErrorIs(t, err, tc.wantErr)
		})
	}
}

func TestUpdateClient_ScopesUpdate(t *testing.T) {
	id := uuid.New()
	existing := &domain.Client{
		ID:             id,
		Name:           "svc",
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$abc$def",
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	var updatedScopes []string
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			c := *existing
			return &c, nil
		},
		updateFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			updatedScopes = c.Scopes
			return c, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	newScopes := []string{"read:users", "write:users"}
	_, err := svc.UpdateClient(context.Background(), id.String(), &api.UpdateClientRequest{
		Scopes: newScopes,
	})
	require.NoError(t, err)
	assert.Equal(t, newScopes, updatedScopes)
}

func TestRotateSecret_NotFound(t *testing.T) {
	repo := &mockClientRepo{} // default returns ErrNotFound
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.RotateSecret(context.Background(), "nonexistent")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestRotateSecret_FindInternalError(t *testing.T) {
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.RotateSecret(context.Background(), "some-id")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestRotateSecret_UpdateError(t *testing.T) {
	id := uuid.New()
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return &domain.Client{
				ID:             id,
				ClientType:     domain.ClientTypeService,
				SecretHash:     "$argon2id$v=19$m=19456,t=2,p=1$abc$def",
				AccessTokenTTL: 900,
				Status:         domain.ClientStatusActive,
				CreatedAt:      time.Now(),
				UpdatedAt:      time.Now(),
			}, nil
		},
		updateFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.RotateSecret(context.Background(), id.String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestListClients_RepoError(t *testing.T) {
	repo := &mockClientRepo{
		listFn: func(_ context.Context, _, _ int, _ bool) ([]*domain.Client, int, error) {
			return nil, 0, fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.ListClients(context.Background(), 1, 20, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestClientCredentialsGrant_TokenIssuerError(t *testing.T) {
	clientID := uuid.New().String()

	var capturedHash string
	setupRepo := &mockClientRepo{
		createFn: func(_ context.Context, c *domain.Client) (*domain.Client, error) {
			capturedHash = c.SecretHash
			return c, nil
		},
	}
	setupSvc := newTestService(setupRepo, &mockTokenIssuer{})
	result, err := setupSvc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "svc-tok-err",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.NoError(t, err)

	activeClient := &domain.Client{
		ID:             uuid.MustParse(clientID),
		ClientType:     domain.ClientTypeService,
		SecretHash:     capturedHash,
		Scopes:         []string{"read:users"},
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return activeClient, nil
		},
	}
	issuer := &mockTokenIssuer{
		issueAccessTokenOnlyFn: func(_ context.Context, _ string, _ []string, _ string, _ time.Duration) (*api.AuthResult, error) {
			return nil, fmt.Errorf("token service unavailable")
		},
	}

	svc := newTestService(repo, issuer)
	_, err = svc.ClientCredentialsGrant(context.Background(), clientID, result.ClientSecret)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestListClients_ReturnsPaginatedResults(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()
	now := time.Now()

	repo := &mockClientRepo{
		listFn: func(_ context.Context, page, perPage int, _ bool) ([]*domain.Client, int, error) {
			return []*domain.Client{
				{ID: id1, Name: "svc1", ClientType: domain.ClientTypeService, Status: domain.ClientStatusActive, CreatedAt: now, UpdatedAt: now},
				{ID: id2, Name: "svc2", ClientType: domain.ClientTypeAgent, Status: domain.ClientStatusActive, CreatedAt: now, UpdatedAt: now},
			}, 2, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	list, err := svc.ListClients(context.Background(), 1, 20, false)
	require.NoError(t, err)
	assert.Equal(t, 2, list.Total)
	assert.Len(t, list.Clients, 2)
}

func TestCreateClient_InvalidClientType(t *testing.T) {
	svc := newTestService(&mockClientRepo{}, &mockTokenIssuer{})

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "bad-type",
		ClientType: "invalid",
		Scopes:     []string{"read:users"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

func TestCreateClient_InternalRepoError(t *testing.T) {
	repo := &mockClientRepo{
		createFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
			return nil, fmt.Errorf("db unavailable")
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "new-svc",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// TestAuthenticateClient_MalformedHash verifies that a malformed secret hash
// returns ErrInvalidCredentials rather than an unexpected error type.
func TestAuthenticateClient_MalformedHash(t *testing.T) {
	clientID := uuid.New().String()
	client := &domain.Client{
		ID:             uuid.MustParse(clientID),
		ClientType:     domain.ClientTypeService,
		SecretHash:     "notavalidhashstring",
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
	}

	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ string) (*domain.Client, error) {
			return client, nil
		},
	}
	svc := newTestService(repo, &mockTokenIssuer{})

	_, err := svc.ClientCredentialsGrant(context.Background(), clientID, "qf_cs_anything")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrUnauthorized)
}
