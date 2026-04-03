package admin_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/qf-studio/auth-service/internal/admin"
	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock ClientRepository ---

type mockClientRepo struct {
	findByIDFn func(ctx context.Context, id string) (*domain.Client, error)
	findAllFn  func(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.Client, int64, error)
	createFn   func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	updateFn   func(ctx context.Context, client *domain.Client) (*domain.Client, error)
	revokeFn   func(ctx context.Context, id string) error
}

func (m *mockClientRepo) FindByID(ctx context.Context, id string) (*domain.Client, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return nil, storage.ErrNotFound
}

func (m *mockClientRepo) FindAll(ctx context.Context, offset, limit int, includeDeleted bool) ([]*domain.Client, int64, error) {
	if m.findAllFn != nil {
		return m.findAllFn(ctx, offset, limit, includeDeleted)
	}
	return []*domain.Client{}, 0, nil
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

func (m *mockClientRepo) Revoke(ctx context.Context, id string) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, id)
	}
	return nil
}

// --- Helpers ---

func newClientSvc(repo admin.ClientRepository) *admin.ClientService {
	return admin.NewClientService(repo, &mockHasher{})
}

func makeClient(id string) *domain.Client {
	now := time.Now().UTC()
	uid := uuid.MustParse(id)
	return &domain.Client{
		ID:             uid,
		Name:           "test-client",
		ClientType:     domain.ClientTypeService,
		SecretHash:     "hashed:secret",
		Scopes:         []string{"read:users"},
		Status:         domain.ClientStatusActive,
		AccessTokenTTL: 3600,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
}

const testClientID = "00000000-0000-0000-0000-000000000001"

// --- ListClients ---

func TestClientService_ListClients(t *testing.T) {
	tests := []struct {
		name        string
		page        int
		perPage     int
		setupRepo   func(*mockClientRepo)
		wantLen     int
		wantTotal   int
		wantPage    int
		wantPerPage int
		wantErr     bool
	}{
		{
			name:    "returns empty list",
			page:    1,
			perPage: 20,
			setupRepo: func(r *mockClientRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.Client, int64, error) {
					return []*domain.Client{}, 0, nil
				}
			},
			wantLen:     0,
			wantTotal:   0,
			wantPage:    1,
			wantPerPage: 20,
		},
		{
			name:    "returns clients with correct metadata",
			page:    1,
			perPage: 10,
			setupRepo: func(r *mockClientRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.Client, int64, error) {
					return []*domain.Client{makeClient(testClientID)}, 1, nil
				}
			},
			wantLen:     1,
			wantTotal:   1,
			wantPage:    1,
			wantPerPage: 10,
		},
		{
			name:    "computes correct offset for page 3",
			page:    3,
			perPage: 10,
			setupRepo: func(r *mockClientRepo) {
				r.findAllFn = func(_ context.Context, offset, limit int, _ bool) ([]*domain.Client, int64, error) {
					assert.Equal(t, 20, offset)
					assert.Equal(t, 10, limit)
					return []*domain.Client{}, 30, nil
				}
			},
			wantTotal: 30,
			wantPage:  3,
		},
		{
			name:    "propagates repository error",
			page:    1,
			perPage: 20,
			setupRepo: func(r *mockClientRepo) {
				r.findAllFn = func(_ context.Context, _, _ int, _ bool) ([]*domain.Client, int64, error) {
					return nil, 0, errors.New("database unavailable")
				}
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newClientSvc(repo).ListClients(context.Background(), tt.page, tt.perPage, false)

			if tt.wantErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			assert.Len(t, result.Clients, tt.wantLen)
			assert.Equal(t, tt.wantTotal, result.Total)
			if tt.wantPage != 0 {
				assert.Equal(t, tt.wantPage, result.Page)
			}
		})
	}
}

// --- GetClient ---

func TestClientService_GetClient(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		setupRepo func(*mockClientRepo)
		wantErrIs error
	}{
		{
			name:     "returns client when found",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.Client, error) {
					return makeClient(id), nil
				}
			},
		},
		{
			name:     "returns ErrNotFound for missing client",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.Client, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
		{
			name:     "propagates unexpected repository error",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.Client, error) {
					return nil, errors.New("connection error")
				}
			},
			wantErrIs: errors.New("any"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newClientSvc(repo).GetClient(context.Background(), tt.clientID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErrIs, api.ErrNotFound) {
					assert.ErrorIs(t, err, api.ErrNotFound)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.clientID, result.ID)
		})
	}
}

// --- CreateClient ---

func TestClientService_CreateClient(t *testing.T) {
	validReq := &api.CreateClientRequest{
		Name:       "my-service",
		ClientType: "service",
		Scopes:     []string{"read:users"},
	}

	tests := []struct {
		name      string
		req       *api.CreateClientRequest
		setupRepo func(*mockClientRepo)
		wantErrIs error
		check     func(*api.AdminClientWithSecret)
	}{
		{
			name: "creates client and returns plaintext secret",
			req:  validReq,
			setupRepo: func(r *mockClientRepo) {
				r.createFn = func(_ context.Context, c *domain.Client) (*domain.Client, error) {
					return c, nil
				}
			},
			check: func(c *api.AdminClientWithSecret) {
				assert.Equal(t, "my-service", c.Name)
				assert.Equal(t, "service", c.ClientType)
				assert.Equal(t, []string{"read:users"}, c.Scopes)
				assert.NotEmpty(t, c.ClientSecret)
				assert.True(t, len(c.ClientSecret) > 10, "secret should be non-trivial length")
				assert.Contains(t, c.ClientSecret, "qf_cs_", "secret must carry the qf_cs_ prefix")
				assert.NotEmpty(t, c.ID)
				assert.Nil(t, c.GracePeriodEnds, "no grace period on initial creation")
			},
		},
		{
			name: "creates agent-type client",
			req:  &api.CreateClientRequest{Name: "my-agent", ClientType: "agent", Scopes: []string{"read:users"}},
			setupRepo: func(r *mockClientRepo) {
				r.createFn = func(_ context.Context, c *domain.Client) (*domain.Client, error) {
					return c, nil
				}
			},
			check: func(c *api.AdminClientWithSecret) {
				assert.Equal(t, "agent", c.ClientType)
			},
		},
		{
			name: "returns ErrConflict on duplicate name",
			req:  validReq,
			setupRepo: func(r *mockClientRepo) {
				r.createFn = func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
					return nil, storage.ErrDuplicateEmail
				}
			},
			wantErrIs: api.ErrConflict,
		},
		{
			name: "propagates hasher error",
			req:  validReq,
			wantErrIs: errors.New("any"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			svc := admin.NewClientService(repo, &mockHasher{})
			if tt.name == "propagates hasher error" {
				svc = admin.NewClientService(repo, &mockHasher{
					hashFn: func(_ string) (string, error) {
						return "", errors.New("argon2 failed")
					},
				})
			}

			result, err := svc.CreateClient(context.Background(), tt.req)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErrIs, api.ErrConflict) {
					assert.ErrorIs(t, err, api.ErrConflict)
				}
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}

// --- UpdateClient ---

func TestClientService_UpdateClient(t *testing.T) {
	newName := "updated-name"
	newScopes := []string{"read:users", "write:users"}

	tests := []struct {
		name      string
		clientID  string
		req       *api.UpdateClientRequest
		setupRepo func(*mockClientRepo)
		wantErrIs error
		check     func(*api.AdminClient)
	}{
		{
			name:     "updates client name",
			clientID: testClientID,
			req:      &api.UpdateClientRequest{Name: &newName},
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.Client, error) {
					return makeClient(id), nil
				}
				r.updateFn = func(_ context.Context, c *domain.Client) (*domain.Client, error) {
					return c, nil
				}
			},
			check: func(c *api.AdminClient) {
				assert.Equal(t, newName, c.Name)
			},
		},
		{
			name:     "updates client scopes",
			clientID: testClientID,
			req:      &api.UpdateClientRequest{Scopes: newScopes},
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.Client, error) {
					return makeClient(id), nil
				}
				r.updateFn = func(_ context.Context, c *domain.Client) (*domain.Client, error) {
					return c, nil
				}
			},
			check: func(c *api.AdminClient) {
				assert.Equal(t, newScopes, c.Scopes)
			},
		},
		{
			name:     "returns ErrNotFound when client missing",
			clientID: testClientID,
			req:      &api.UpdateClientRequest{Name: &newName},
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.Client, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newClientSvc(repo).UpdateClient(context.Background(), tt.clientID, tt.req)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, result)
			if tt.check != nil {
				tt.check(result)
			}
		})
	}
}

// --- DeleteClient ---

func TestClientService_DeleteClient(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		setupRepo func(*mockClientRepo)
		wantErrIs error
	}{
		{
			name:     "revokes client successfully",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.revokeFn = func(_ context.Context, _ string) error {
					return nil
				}
			},
		},
		{
			name:     "returns ErrNotFound for missing client",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.revokeFn = func(_ context.Context, _ string) error {
					return storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
		{
			name:     "propagates repository error",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.revokeFn = func(_ context.Context, _ string) error {
					return errors.New("db error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			err := newClientSvc(repo).DeleteClient(context.Background(), tt.clientID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}
		})
	}
}

// --- RotateSecret ---

func TestClientService_RotateSecret(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		setupRepo func(*mockClientRepo)
		wantErrIs error
		check     func(*api.AdminClientWithSecret)
	}{
		{
			name:     "rotates secret and returns new plaintext with grace period",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.Client, error) {
					return makeClient(id), nil
				}
				r.updateFn = func(_ context.Context, c *domain.Client) (*domain.Client, error) {
					return c, nil
				}
			},
			check: func(c *api.AdminClientWithSecret) {
				assert.NotEmpty(t, c.ClientSecret)
				assert.Contains(t, c.ClientSecret, "qf_cs_", "new secret must have qf_cs_ prefix")
				assert.NotNil(t, c.GracePeriodEnds, "grace period must be set after rotation")
				assert.True(t, c.GracePeriodEnds.After(time.Now()), "grace period must be in the future")
			},
		},
		{
			name:     "returns ErrNotFound when client missing",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, _ string) (*domain.Client, error) {
					return nil, storage.ErrNotFound
				}
			},
			wantErrIs: api.ErrNotFound,
		},
		{
			name:     "propagates update error after successful fetch",
			clientID: testClientID,
			setupRepo: func(r *mockClientRepo) {
				r.findByIDFn = func(_ context.Context, id string) (*domain.Client, error) {
					return makeClient(id), nil
				}
				r.updateFn = func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
					return nil, errors.New("db error")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			repo := &mockClientRepo{}
			if tt.setupRepo != nil {
				tt.setupRepo(repo)
			}

			result, err := newClientSvc(repo).RotateSecret(context.Background(), tt.clientID)

			if tt.wantErrIs != nil {
				require.Error(t, err)
				assert.ErrorIs(t, err, tt.wantErrIs)
				return
			}

			if tt.check != nil {
				require.NoError(t, err)
				require.NotNil(t, result)
				tt.check(result)
			}
		})
	}
}
