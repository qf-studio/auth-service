package admin

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/api"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- stateful mock APIKeyRepository ---
//
// Unlike the other admin mocks in this package (which return canned
// fixtures), this one keeps real state so it can reproduce the grace-window
// lookup semantics that PostgresAPIKeyRepository.FindByKeyHash implements in
// SQL (key_hash = $1 OR (previous_key_hash = $1 AND previous_key_expires_at
// > NOW())) — needed to exercise rotate/grace-period behavior end to end.

type mockAPIKeyRepo struct {
	mu   sync.Mutex
	keys map[uuid.UUID]*domain.APIKey
}

func newMockAPIKeyRepo() *mockAPIKeyRepo {
	return &mockAPIKeyRepo{keys: make(map[uuid.UUID]*domain.APIKey)}
}

func (m *mockAPIKeyRepo) put(k *domain.APIKey) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *k
	m.keys[k.ID] = &cp
}

func (m *mockAPIKeyRepo) List(_ context.Context, _ uuid.UUID, _, _ int, _ string) ([]*domain.APIKey, int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain.APIKey, 0, len(m.keys))
	for _, k := range m.keys {
		cp := *k
		out = append(out, &cp)
	}
	return out, len(out), nil
}

func (m *mockAPIKeyRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*domain.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return nil, storage.ErrNotFound
	}
	cp := *k
	return &cp, nil
}

func (m *mockAPIKeyRepo) FindByKeyHash(_ context.Context, _ uuid.UUID, keyHash string) (*domain.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, k := range m.keys {
		if k.KeyHash == keyHash {
			cp := *k
			return &cp, nil
		}
		if k.PreviousKeyHash == keyHash && k.PreviousKeyExpiresAt != nil && k.PreviousKeyExpiresAt.After(time.Now()) {
			cp := *k
			return &cp, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (m *mockAPIKeyRepo) Create(_ context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := *key
	m.keys[key.ID] = &cp
	out := *key
	return &out, nil
}

func (m *mockAPIKeyRepo) Update(_ context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.keys[key.ID]; !ok {
		return nil, storage.ErrNotFound
	}
	cp := *key
	m.keys[key.ID] = &cp
	out := *key
	return &out, nil
}

func (m *mockAPIKeyRepo) Revoke(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return storage.ErrNotFound
	}
	if k.Status != domain.APIKeyStatusActive {
		return storage.ErrAlreadyDeleted
	}
	k.Status = domain.APIKeyStatusRevoked
	return nil
}

func (m *mockAPIKeyRepo) RotateKey(_ context.Context, _ uuid.UUID, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return storage.ErrNotFound
	}
	k.PreviousKeyHash = k.KeyHash
	grace := gracePeriodEnds
	k.PreviousKeyExpiresAt = &grace
	k.KeyHash = newKeyHash
	return nil
}

func (m *mockAPIKeyRepo) UpdateLastUsed(_ context.Context, _ uuid.UUID, id uuid.UUID) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, ok := m.keys[id]
	if !ok {
		return storage.ErrNotFound
	}
	now := time.Now().UTC()
	k.LastUsedAt = &now
	return nil
}

// --- helpers ---

func newTestAPIKeyService(repo storage.APIKeyRepository) *APIKeyService {
	return NewAPIKeyService(repo, zap.NewNop(), audit.NopLogger{})
}

func testAPIKey(id uuid.UUID, rawKey string) *domain.APIKey {
	now := time.Now().UTC()
	return &domain.APIKey{
		ID:        id,
		TenantID:  uuid.New(),
		ClientID:  uuid.New(),
		Name:      "test-key",
		KeyHash:   hashAPIKey(rawKey),
		KeyPrefix: rawKey[:len(apiKeyPrefix)+8],
		Scopes:    []string{"read:users"},
		RateLimit: defaultRateLimit,
		Status:    domain.APIKeyStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// --- ValidateAPIKey (table-driven) ---

func TestAPIKeyService_ValidateAPIKey(t *testing.T) {
	now := time.Now().UTC()
	repo := newMockAPIKeyRepo()

	activeID := uuid.New()
	repo.put(testAPIKey(activeID, "qf_ak_activekeyvalue"))

	expiredID := uuid.New()
	expired := testAPIKey(expiredID, "qf_ak_expiredkeyvalue")
	expiredAt := now.Add(-time.Hour)
	expired.ExpiresAt = &expiredAt
	repo.put(expired)

	revokedID := uuid.New()
	revoked := testAPIKey(revokedID, "qf_ak_revokedkeyvalue")
	revoked.Status = domain.APIKeyStatusRevoked
	repo.put(revoked)

	// A rotated key: current key is "new", previous key still valid within
	// the grace window.
	rotatedID := uuid.New()
	rotated := testAPIKey(rotatedID, "qf_ak_rotatednewvalue")
	rotated.PreviousKeyHash = hashAPIKey("qf_ak_rotatedoldvalue")
	graceEnd := now.Add(time.Hour)
	rotated.PreviousKeyExpiresAt = &graceEnd
	repo.put(rotated)

	// A rotated key whose grace window has already elapsed.
	staleID := uuid.New()
	stale := testAPIKey(staleID, "qf_ak_stalenewvalue")
	stale.PreviousKeyHash = hashAPIKey("qf_ak_staleoldvalue")
	gracePast := now.Add(-time.Hour)
	stale.PreviousKeyExpiresAt = &gracePast
	repo.put(stale)

	svc := newTestAPIKeyService(repo)

	tests := []struct {
		name    string
		rawKey  string
		wantErr bool
	}{
		{name: "valid active key", rawKey: "qf_ak_activekeyvalue", wantErr: false},
		{name: "unknown key", rawKey: "qf_ak_neverissuedvalue", wantErr: true},
		{name: "revoked key rejected", rawKey: "qf_ak_revokedkeyvalue", wantErr: true},
		{name: "expired key rejected", rawKey: "qf_ak_expiredkeyvalue", wantErr: true},
		{name: "rotated: old key valid within grace window", rawKey: "qf_ak_rotatedoldvalue", wantErr: false},
		{name: "rotated: new key valid immediately", rawKey: "qf_ak_rotatednewvalue", wantErr: false},
		{name: "rotated: old key rejected after grace window", rawKey: "qf_ak_staleoldvalue", wantErr: true},
		{name: "rotated: new key still valid after old key's grace expired", rawKey: "qf_ak_stalenewvalue", wantErr: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := svc.ValidateAPIKey(context.Background(), tt.rawKey)
			if tt.wantErr {
				require.Error(t, err)
				assert.Nil(t, info)
				return
			}
			require.NoError(t, err)
			require.NotNil(t, info)
			assert.NotEmpty(t, info.ClientID)
		})
	}
}

// --- Full lifecycle: create -> validate -> rotate -> validate (old+new) -> revoke -> rejected ---

func TestAPIKeyService_FullLifecycle(t *testing.T) {
	repo := newMockAPIKeyRepo()
	svc := newTestAPIKeyService(repo)
	ctx := domain.WithTenantID(context.Background(), uuid.New())

	created, err := svc.CreateAPIKey(ctx, &api.CreateAPIKeyRequest{
		ClientID: uuid.New().String(),
		Name:     "lifecycle-key",
	})
	require.NoError(t, err)
	require.NotEmpty(t, created.Key)
	firstKey := created.Key

	// Validate the freshly created key succeeds.
	info, err := svc.ValidateAPIKey(ctx, firstKey)
	require.NoError(t, err)
	assert.Equal(t, created.ClientID, info.ClientID)

	// Rotate: a new key is issued, old key still works within the grace period.
	rotated, err := svc.RotateAPIKey(ctx, created.ID)
	require.NoError(t, err)
	require.NotEmpty(t, rotated.Key)
	require.NotEqual(t, firstKey, rotated.Key)
	require.NotNil(t, rotated.GracePeriodEnds)
	secondKey := rotated.Key

	_, err = svc.ValidateAPIKey(ctx, firstKey)
	assert.NoError(t, err, "old key should still validate within the grace period")

	_, err = svc.ValidateAPIKey(ctx, secondKey)
	assert.NoError(t, err, "new key should validate immediately")

	// Revoke: both old and new keys must be rejected afterward.
	err = svc.RevokeAPIKey(ctx, created.ID)
	require.NoError(t, err)

	_, err = svc.ValidateAPIKey(ctx, secondKey)
	assert.Error(t, err, "new key should be rejected after revoke")

	_, err = svc.ValidateAPIKey(ctx, firstKey)
	assert.Error(t, err, "old key should be rejected after revoke")
}
