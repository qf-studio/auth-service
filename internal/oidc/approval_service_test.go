package oidc_test

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
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/oidc"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/storage/mocks"
)

func newTestApprovalService(repo *mocks.MockClientRepository, hasher *fakeHasher) *oidc.ApprovalService {
	if hasher == nil {
		hasher = &fakeHasher{}
	}
	return oidc.NewApprovalService(repo, hasher, zap.NewNop(), audit.NopLogger{})
}

// ────────────────────────────────────────────────────────────────────────────
// CreateThirdPartyClient
// ────────────────────────────────────────────────────────────────────────────

func TestApprovalService_CreateThirdPartyClient_ConfidentialClient(t *testing.T) {
	var created *domain.Client
	repo := &mocks.MockClientRepository{
		CreateFn: func(_ context.Context, client *domain.Client) (*domain.Client, error) {
			created = client
			return client, nil
		},
	}
	svc := newTestApprovalService(repo, nil)

	resp, err := svc.CreateThirdPartyClient(context.Background(), &api.CreateClientRequest{
		Name:         "third-party-app",
		ClientType:   string(domain.ClientTypeService),
		Scopes:       []string{"openid"},
		RedirectURIs: []string{"https://thirdparty.example.com/callback"},
	})
	require.NoError(t, err)

	require.NotNil(t, created)
	assert.Equal(t, "third-party", created.Owner)
	assert.Equal(t, domain.ClientStatusSuspended, created.Status)
	assert.NotEmpty(t, created.SecretHash)

	assert.NotEmpty(t, resp.ClientSecret)
	assert.Contains(t, resp.ClientSecret, "qf_cs_")
	assert.Equal(t, "third-party-app", resp.Name)
}

func TestApprovalService_CreateThirdPartyClient_PublicClient_NoSecret(t *testing.T) {
	var created *domain.Client
	repo := &mocks.MockClientRepository{
		CreateFn: func(_ context.Context, client *domain.Client) (*domain.Client, error) {
			created = client
			return client, nil
		},
	}
	svc := newTestApprovalService(repo, nil)

	resp, err := svc.CreateThirdPartyClient(context.Background(), &api.CreateClientRequest{
		Name:         "third-party-spa",
		ClientType:   string(domain.ClientTypePublic),
		RedirectURIs: []string{"https://thirdparty.example.com/callback"},
	})
	require.NoError(t, err)

	require.NotNil(t, created)
	assert.Empty(t, created.SecretHash)
	assert.Equal(t, domain.ClientStatusSuspended, created.Status)
	assert.Empty(t, resp.ClientSecret)
}

func TestApprovalService_CreateThirdPartyClient_DuplicateName(t *testing.T) {
	repo := &mocks.MockClientRepository{
		CreateFn: func(_ context.Context, _ *domain.Client) (*domain.Client, error) {
			return nil, storage.ErrDuplicateClient
		},
	}
	svc := newTestApprovalService(repo, nil)

	_, err := svc.CreateThirdPartyClient(context.Background(), &api.CreateClientRequest{
		Name:         "existing-app",
		ClientType:   string(domain.ClientTypeService),
		RedirectURIs: []string{"https://thirdparty.example.com/callback"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrConflict)
}

func TestApprovalService_CreateThirdPartyClient_HashFailure(t *testing.T) {
	repo := &mocks.MockClientRepository{
		CreateFn: func(_ context.Context, client *domain.Client) (*domain.Client, error) { return client, nil },
	}
	hasher := &fakeHasher{
		hashFn: func(_ string) (string, error) { return "", fmt.Errorf("hash failed") },
	}
	svc := newTestApprovalService(repo, hasher)

	_, err := svc.CreateThirdPartyClient(context.Background(), &api.CreateClientRequest{
		Name:         "broken-app",
		ClientType:   string(domain.ClientTypeService),
		RedirectURIs: []string{"https://thirdparty.example.com/callback"},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrInternalError)
}

// ────────────────────────────────────────────────────────────────────────────
// ApproveClient
// ────────────────────────────────────────────────────────────────────────────

func TestApprovalService_ApproveClient_Success(t *testing.T) {
	clientID := uuid.New()
	existing := &domain.Client{ID: clientID, Name: "pending-app", Status: domain.ClientStatusSuspended}
	var activatedID uuid.UUID
	repo := &mocks.MockClientRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.Client, error) {
			require.Equal(t, clientID, id)
			return existing, nil
		},
		ActivateFn: func(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
			activatedID = id
			return nil
		},
	}
	svc := newTestApprovalService(repo, nil)

	info, err := svc.ApproveClient(context.Background(), clientID.String())
	require.NoError(t, err)
	assert.Equal(t, clientID, activatedID)
	assert.Equal(t, clientID.String(), info.ClientID)
	assert.Equal(t, "pending-app", info.ClientName)
	assert.True(t, info.Approved)
	require.NotNil(t, info.ApprovedAt)
	assert.WithinDuration(t, time.Now().UTC(), *info.ApprovedAt, time.Minute)
}

func TestApprovalService_ApproveClient_InvalidID(t *testing.T) {
	svc := newTestApprovalService(&mocks.MockClientRepository{}, nil)

	_, err := svc.ApproveClient(context.Background(), "not-a-uuid")
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestApprovalService_ApproveClient_NotFound(t *testing.T) {
	repo := &mocks.MockClientRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*domain.Client, error) {
			return nil, storage.ErrNotFound
		},
	}
	svc := newTestApprovalService(repo, nil)

	_, err := svc.ApproveClient(context.Background(), uuid.New().String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}

func TestApprovalService_ApproveClient_RevokedRejected(t *testing.T) {
	clientID := uuid.New()
	existing := &domain.Client{ID: clientID, Name: "revoked-app", Status: domain.ClientStatusRevoked}
	repo := &mocks.MockClientRepository{
		FindByIDFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) (*domain.Client, error) { return existing, nil },
		ActivateFn: func(_ context.Context, _ uuid.UUID, _ uuid.UUID) error {
			return storage.ErrNotFound
		},
	}
	svc := newTestApprovalService(repo, nil)

	_, err := svc.ApproveClient(context.Background(), clientID.String())
	require.Error(t, err)
	assert.ErrorIs(t, err, api.ErrNotFound)
}
