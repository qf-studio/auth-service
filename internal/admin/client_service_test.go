package admin

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock ClientRepository ---

type mockClientRepo struct {
	listFn             func(ctx context.Context, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error)
	findByIDFn         func(ctx context.Context, id uuid.UUID) (*domain.Client, error)
	findByNameFn       func(ctx context.Context, name string) (*domain.Client, error)
	createFn           func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	updateFn           func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	updateSecretHashFn func(ctx context.Context, id uuid.UUID, secretHash string) error
	rotateSecretFn     func(ctx context.Context, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error
	softDeleteFn       func(ctx context.Context, id uuid.UUID) error
}

func (m *mockClientRepo) List(ctx context.Context, limit, offset int, clientType string, includeRevoked bool) ([]*domain.Client, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, limit, offset, clientType, includeRevoked)
	}
	return []*domain.Client{testClient()}, 1, nil
}

func (m *mockClientRepo) FindByID(ctx context.Context, id uuid.UUID) (*domain.Client, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	c := testClient()
	c.ID = id
	return c, nil
}

func (m *mockClientRepo) FindByName(ctx context.Context, name string) (*domain.Client, error) {
	if m.findByNameFn != nil {
		return m.findByNameFn(ctx, name)
	}
	c := testClient()
	c.Name = name
	return c, nil
}

func (m *mockClientRepo) Create(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	if m.createFn != nil {
		return m.createFn(ctx, client)
	}
	return client, nil
}

func (m *mockClientRepo) Update(ctx context.Context, client *domain.Client) (*domain.Client, error) {
	if m.updateFn != nil {
		return m.updateFn(ctx, client)
	}
	return client, nil
}

func (m *mockClientRepo) UpdateSecretHash(ctx context.Context, id uuid.UUID, secretHash string) error {
	if m.updateSecretHashFn != nil {
		return m.updateSecretHashFn(ctx, id, secretHash)
	}
	return nil
}

func (m *mockClientRepo) RotateSecret(ctx context.Context, id uuid.UUID, newSecretHash string, gracePeriodEnds time.Time) error {
	if m.rotateSecretFn != nil {
		return m.rotateSecretFn(ctx, id, newSecretHash, gracePeriodEnds)
	}
	return nil
}

func (m *mockClientRepo) SoftDelete(ctx context.Context, id uuid.UUID) error {
	if m.softDeleteFn != nil {
		return m.softDeleteFn(ctx, id)
	}
	return nil
}

// --- Helpers ---

func testClient() *domain.Client {
	now := time.Now()
	return &domain.Client{
		ID:             uuid.New(),
		Name:           "test-service",
		ClientType:     domain.ClientTypeService,
		SecretHash:     "$argon2id$mock$secret",
		Scopes:         []string{"read:users"},
		Owner:          "admin",
		AccessTokenTTL: 900,
		Status:         domain.ClientStatusActive,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

func newTestClientService(repo *mockClientRepo) *ClientService {
	return NewClientService(repo, &mockHasher{}, zap.NewNop())
}

// --- ListClients ---

func TestClientService_ListClients(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	result, err := svc.ListClients(context.Background(), 1, 20, "", false)
	require.NoError(t, err)
	assert.Equal(t, 1, result.Total)
	assert.Len(t, result.Clients, 1)
}

func TestClientService_ListClients_Error(t *testing.T) {
	repo := &mockClientRepo{
		listFn: func(_ context.Context, _, _ int, _ string, _ bool) ([]*domain.Client, int, error) {
			return nil, 0, fmt.Errorf("db error")
		},
	}
	svc := newTestClientService(repo)

	_, err := svc.ListClients(context.Background(), 1, 20, "", false)
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// --- GetClient ---

func TestClientService_GetClient(t *testing.T) {
	clientID := uuid.New()
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, id uuid.UUID) (*domain.Client, error) {
			assert.Equal(t, clientID, id)
			c := testClient()
			c.ID = id
			return c, nil
		},
	}
	svc := newTestClientService(repo)

	client, err := svc.GetClient(context.Background(), clientID.String())
	require.NoError(t, err)
	assert.Equal(t, clientID.String(), client.ID)
}

func TestClientService_GetClient_InvalidID(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	_, err := svc.GetClient(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestClientService_GetClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestClientService(repo)

	_, err := svc.GetClient(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- CreateClient ---

func TestClientService_CreateClient(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	req := &api.CreateClientRequest{
		Name:       "my-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	}
	result, err := svc.CreateClient(context.Background(), req)
	require.NoError(t, err)
	assert.Equal(t, "my-service", result.Name)
	assert.Equal(t, "service", result.ClientType)
	assert.Contains(t, result.ClientSecret, clientSecretPrefix)
}

func TestClientService_CreateClient_Conflict(t *testing.T) {
	repo := &mockClientRepo{
		createFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
			return nil, fmt.Errorf("dup: %w", storage.ErrDuplicateClient)
		},
	}
	svc := newTestClientService(repo)

	_, err := svc.CreateClient(context.Background(), &api.CreateClientRequest{
		Name:       "dup",
		ClientType: "service",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

// --- UpdateClient ---

func TestClientService_UpdateClient(t *testing.T) {
	clientID := uuid.New()
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, id uuid.UUID) (*domain.Client, error) {
			c := testClient()
			c.ID = id
			return c, nil
		},
	}
	svc := newTestClientService(repo)

	name := "updated-name"
	client, err := svc.UpdateClient(context.Background(), clientID.String(), &api.UpdateClientRequest{Name: &name})
	require.NoError(t, err)
	assert.Equal(t, "updated-name", client.Name)
}

func TestClientService_UpdateClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.Client, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestClientService(repo)

	name := "nope"
	_, err := svc.UpdateClient(context.Background(), uuid.New().String(), &api.UpdateClientRequest{Name: &name})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- DeleteClient ---

func TestClientService_DeleteClient(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	err := svc.DeleteClient(context.Background(), uuid.New().String())
	require.NoError(t, err)
}

func TestClientService_DeleteClient_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		softDeleteFn: func(_ context.Context, _ uuid.UUID) error {
			return fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestClientService(repo)

	err := svc.DeleteClient(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestClientService_DeleteClient_InvalidID(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	err := svc.DeleteClient(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- RotateSecret ---

func TestClientService_RotateSecret(t *testing.T) {
	clientID := uuid.New()
	repo := &mockClientRepo{
		findByIDFn: func(_ context.Context, id uuid.UUID) (*domain.Client, error) {
			c := testClient()
			c.ID = id
			return c, nil
		},
	}
	svc := newTestClientService(repo)

	result, err := svc.RotateSecret(context.Background(), clientID.String())
	require.NoError(t, err)
	assert.Contains(t, result.ClientSecret, clientSecretPrefix)
	assert.NotNil(t, result.GracePeriodEnds)
}

func TestClientService_RotateSecret_NotFound(t *testing.T) {
	repo := &mockClientRepo{
		rotateSecretFn: func(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
			return fmt.Errorf("not found: %w", storage.ErrNotFound)
		},
	}
	svc := newTestClientService(repo)

	_, err := svc.RotateSecret(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestClientService_RotateSecret_InvalidID(t *testing.T) {
	svc := newTestClientService(&mockClientRepo{})

	_, err := svc.RotateSecret(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

// --- generateClientSecret ---

func TestGenerateClientSecret(t *testing.T) {
	secret, err := generateClientSecret()
	require.NoError(t, err)
	assert.True(t, len(secret) > len(clientSecretPrefix))
	assert.Contains(t, secret, clientSecretPrefix)
}

// --- domainClientToAdmin ---

func TestDomainClientToAdmin(t *testing.T) {
	c := testClient()
	admin := domainClientToAdmin(c)

	assert.Equal(t, c.ID.String(), admin.ID)
	assert.Equal(t, c.Name, admin.Name)
	assert.Equal(t, string(c.ClientType), admin.ClientType)
	assert.Equal(t, c.Scopes, admin.Scopes)
}
