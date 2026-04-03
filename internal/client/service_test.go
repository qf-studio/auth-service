package client

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
)

// ── Mock repository ──────────────────────────────────────────────────────

type mockRepo struct {
	mu      sync.Mutex
	clients map[uuid.UUID]*domain.Client
}

func newMockRepo() *mockRepo {
	return &mockRepo{clients: make(map[uuid.UUID]*domain.Client)}
}

func (m *mockRepo) Create(_ context.Context, c *domain.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[c.ID] = c
	return nil
}

func (m *mockRepo) GetByID(_ context.Context, id uuid.UUID) (*domain.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return nil, ErrClientNotFound
	}
	return c, nil
}

func (m *mockRepo) GetByName(_ context.Context, name string) (*domain.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, c := range m.clients {
		if c.Name == name {
			return c, nil
		}
	}
	return nil, ErrClientNotFound
}

func (m *mockRepo) List(_ context.Context, owner string) ([]*domain.Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*domain.Client
	for _, c := range m.clients {
		if c.Owner == owner {
			out = append(out, c)
		}
	}
	return out, nil
}

func (m *mockRepo) Update(_ context.Context, c *domain.Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[c.ID]; !ok {
		return ErrClientNotFound
	}
	m.clients[c.ID] = c
	return nil
}

func (m *mockRepo) Delete(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.clients[id]; !ok {
		return ErrClientNotFound
	}
	delete(m.clients, id)
	return nil
}

func (m *mockRepo) UpdateLastUsed(_ context.Context, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return ErrClientNotFound
	}
	now := time.Now().UTC()
	c.LastUsedAt = &now
	return nil
}

// ── Helpers ──────────────────────────────────────────────────────────────

func testArgonConfig() config.Argon2Config {
	return config.Argon2Config{
		Memory:      4096,  // low for fast tests
		Time:        1,
		Parallelism: 1,
		Pepper:      "test-pepper",
	}
}

func newTestService() (*Service, *mockRepo) {
	repo := newMockRepo()
	logger, _ := zap.NewDevelopment()
	svc := NewService(repo, testArgonConfig(), logger)
	return svc, repo
}

// ── CreateClient tests ──────────────────────────────────────────────────

func TestCreateClient(t *testing.T) {
	tests := []struct {
		name           string
		clientName     string
		clientType     domain.ClientType
		scopes         []string
		owner          string
		accessTokenTTL int
		wantErr        bool
	}{
		{
			name:           "service client",
			clientName:     "payment-service",
			clientType:     domain.ClientTypeService,
			scopes:         []string{"payments:read", "payments:write"},
			owner:          "platform",
			accessTokenTTL: 900,
		},
		{
			name:           "agent client",
			clientName:     "code-agent",
			clientType:     domain.ClientTypeAgent,
			scopes:         []string{"code:execute"},
			owner:          "user-123",
			accessTokenTTL: 300,
		},
		{
			name:           "invalid client type",
			clientName:     "bad-client",
			clientType:     domain.ClientType("invalid"),
			scopes:         []string{"read"},
			owner:          "owner",
			accessTokenTTL: 900,
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, repo := newTestService()
			ctx := context.Background()

			result, err := svc.CreateClient(ctx, tt.clientName, tt.clientType, tt.scopes, tt.owner, tt.accessTokenTTL)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)

			// Verify plaintext secret format.
			assert.Contains(t, result.PlainSecret, secretPrefix)
			assert.Len(t, result.PlainSecret, len(secretPrefix)+secretBytes*2) // prefix + hex-encoded 32 bytes

			// Verify client fields.
			assert.Equal(t, tt.clientName, result.Client.Name)
			assert.Equal(t, tt.clientType, result.Client.ClientType)
			assert.Equal(t, tt.scopes, result.Client.Scopes)
			assert.Equal(t, tt.owner, result.Client.Owner)
			assert.Equal(t, tt.accessTokenTTL, result.Client.AccessTokenTTL)
			assert.Equal(t, domain.ClientStatusActive, result.Client.Status)
			assert.NotEqual(t, uuid.Nil, result.Client.ID)

			// Secret hash stored, not plaintext.
			stored, err := repo.GetByID(ctx, result.Client.ID)
			require.NoError(t, err)
			assert.NotEmpty(t, stored.SecretHash)
			assert.NotContains(t, stored.SecretHash, secretPrefix) // hash, not plain
			assert.Contains(t, stored.SecretHash, "$")             // salt$hash format
		})
	}
}

// ── AuthenticateClient tests ─────────────────────────────────────────────

func TestAuthenticateClient(t *testing.T) {
	svc, _ := newTestService()
	ctx := context.Background()

	// Create a client to authenticate against.
	result, err := svc.CreateClient(ctx, "auth-test-svc", domain.ClientTypeService, []string{"read"}, "owner", 900)
	require.NoError(t, err)

	clientID := result.Client.ID
	validSecret := result.PlainSecret

	tests := []struct {
		name      string
		clientID  uuid.UUID
		secret    string
		wantErr   error
		wantNil   bool
	}{
		{
			name:     "valid credentials",
			clientID: clientID,
			secret:   validSecret,
		},
		{
			name:     "wrong secret",
			clientID: clientID,
			secret:   "qf_cs_0000000000000000000000000000000000000000000000000000000000000000",
			wantErr:  ErrInvalidCredentials,
			wantNil:  true,
		},
		{
			name:     "non-existent client",
			clientID: uuid.New(),
			secret:   validSecret,
			wantErr:  ErrInvalidCredentials,
			wantNil:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, err := svc.AuthenticateClient(ctx, tt.clientID, tt.secret)

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.Nil(t, client)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, client)
			assert.Equal(t, clientID, client.ID)
		})
	}
}

func TestAuthenticateClient_SuspendedClient(t *testing.T) {
	svc, repo := newTestService()
	ctx := context.Background()

	result, err := svc.CreateClient(ctx, "suspended-svc", domain.ClientTypeService, []string{"read"}, "owner", 900)
	require.NoError(t, err)

	// Suspend the client.
	stored, err := repo.GetByID(ctx, result.Client.ID)
	require.NoError(t, err)
	stored.Status = domain.ClientStatusSuspended
	err = repo.Update(ctx, stored)
	require.NoError(t, err)

	client, err := svc.AuthenticateClient(ctx, result.Client.ID, result.PlainSecret)
	require.ErrorIs(t, err, ErrClientSuspended)
	assert.Nil(t, client)
}

func TestAuthenticateClient_UpdatesLastUsed(t *testing.T) {
	svc, repo := newTestService()
	ctx := context.Background()

	result, err := svc.CreateClient(ctx, "lastused-svc", domain.ClientTypeService, []string{"read"}, "owner", 900)
	require.NoError(t, err)

	// Before auth, last_used_at is nil.
	stored, err := repo.GetByID(ctx, result.Client.ID)
	require.NoError(t, err)
	assert.Nil(t, stored.LastUsedAt)

	// After successful auth, last_used_at is set.
	_, err = svc.AuthenticateClient(ctx, result.Client.ID, result.PlainSecret)
	require.NoError(t, err)

	stored, err = repo.GetByID(ctx, result.Client.ID)
	require.NoError(t, err)
	assert.NotNil(t, stored.LastUsedAt)
}

// ── Secret generation and hashing tests ─────────────────────────────────

func TestGenerateSecret(t *testing.T) {
	s1, err := generateSecret()
	require.NoError(t, err)
	s2, err := generateSecret()
	require.NoError(t, err)

	assert.Contains(t, s1, secretPrefix)
	assert.Contains(t, s2, secretPrefix)
	assert.NotEqual(t, s1, s2, "secrets must be unique")
}

func TestHashAndVerify(t *testing.T) {
	svc, _ := newTestService()

	secret := "qf_cs_abcdef1234567890abcdef1234567890abcdef1234567890abcdef12345678"

	hash, err := svc.hashSecret(secret)
	require.NoError(t, err)

	assert.True(t, svc.verifySecret(secret, hash), "correct secret should verify")
	assert.False(t, svc.verifySecret("wrong-secret", hash), "wrong secret should not verify")
	assert.False(t, svc.verifySecret(secret, "invalid-hash"), "malformed hash should not verify")
}
