package apikey

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/domain"
)

// --- Mock Repository ---

type mockRepo struct {
	createFn       func(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error)
	findByIDFn     func(ctx context.Context, id uuid.UUID) (*domain.APIKey, error)
	findByKeyHashFn func(ctx context.Context, keyHash string) (*domain.APIKey, error)
	updateLastUsedFn func(ctx context.Context, id uuid.UUID, t time.Time) error
	rotateKeyFn    func(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error
	revokeFn       func(ctx context.Context, id uuid.UUID) error
}

func (m *mockRepo) Create(ctx context.Context, key *domain.APIKey) (*domain.APIKey, error) {
	if m.createFn != nil {
		return m.createFn(ctx, key)
	}
	return key, nil
}

func (m *mockRepo) FindByID(ctx context.Context, id uuid.UUID) (*domain.APIKey, error) {
	if m.findByIDFn != nil {
		return m.findByIDFn(ctx, id)
	}
	return testAPIKey(id), nil
}

func (m *mockRepo) FindByKeyHash(ctx context.Context, keyHash string) (*domain.APIKey, error) {
	if m.findByKeyHashFn != nil {
		return m.findByKeyHashFn(ctx, keyHash)
	}
	return testAPIKey(uuid.New()), nil
}

func (m *mockRepo) UpdateLastUsed(ctx context.Context, id uuid.UUID, t time.Time) error {
	if m.updateLastUsedFn != nil {
		return m.updateLastUsedFn(ctx, id, t)
	}
	return nil
}

func (m *mockRepo) RotateKey(ctx context.Context, id uuid.UUID, newKeyHash string, gracePeriodEnds time.Time) error {
	if m.rotateKeyFn != nil {
		return m.rotateKeyFn(ctx, id, newKeyHash, gracePeriodEnds)
	}
	return nil
}

func (m *mockRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if m.revokeFn != nil {
		return m.revokeFn(ctx, id)
	}
	return nil
}

// --- Mock Hasher ---

type mockHasher struct {
	hashFn   func(password string) (string, error)
	verifyFn func(password, hash string) (bool, error)
}

func (m *mockHasher) Hash(password string) (string, error) {
	if m.hashFn != nil {
		return m.hashFn(password)
	}
	return "$argon2id$mock$" + password, nil
}

func (m *mockHasher) Verify(password, hash string) (bool, error) {
	if m.verifyFn != nil {
		return m.verifyFn(password, hash)
	}
	return hash == "$argon2id$mock$"+password, nil
}

// --- Helpers ---

func testAPIKey(id uuid.UUID) *domain.APIKey {
	now := time.Now().UTC()
	return &domain.APIKey{
		ID:        id,
		ClientID:  uuid.New(),
		Name:      "test-key",
		KeyHash:   "$argon2id$mock$hash",
		Scopes:    []string{"read:data"},
		RateLimit: 100,
		Status:    domain.APIKeyStatusActive,
		CreatedAt: now,
		UpdatedAt: now,
	}
}

func newTestService(repo *mockRepo) *Service {
	return NewService(repo, &mockHasher{}, nil, zap.NewNop(), audit.NopLogger{})
}

func newTestServiceWithRedis(repo *mockRepo, rdb *redis.Client) *Service {
	return NewService(repo, &mockHasher{}, rdb, zap.NewNop(), audit.NopLogger{})
}

// --- generateAPIKey ---

func TestGenerateAPIKey(t *testing.T) {
	key, err := generateAPIKey()
	require.NoError(t, err)
	assert.True(t, len(key) > len(apiKeyPrefix), "key must be longer than prefix")
	assert.Contains(t, key, apiKeyPrefix)
	// 16 bytes hex = 32 chars + prefix
	assert.Len(t, key, len(apiKeyPrefix)+32)
}

func TestGenerateAPIKey_Uniqueness(t *testing.T) {
	keys := make(map[string]struct{})
	for i := 0; i < 100; i++ {
		key, err := generateAPIKey()
		require.NoError(t, err)
		_, exists := keys[key]
		assert.False(t, exists, "duplicate key generated")
		keys[key] = struct{}{}
	}
}

// --- CreateAPIKey ---

func TestService_CreateAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		repo      *mockRepo
		hasher    *mockHasher
		clientID  uuid.UUID
		keyName   string
		scopes    []string
		rateLimit int
		expiresAt *time.Time
		wantErr   bool
		check     func(t *testing.T, result *CreateResult)
	}{
		{
			name:      "success",
			repo:      &mockRepo{},
			clientID:  uuid.New(),
			keyName:   "my-key",
			scopes:    []string{"read:data"},
			rateLimit: 100,
			check: func(t *testing.T, result *CreateResult) {
				assert.Contains(t, result.PlaintextKey, apiKeyPrefix)
				assert.Equal(t, "my-key", result.APIKey.Name)
				assert.Equal(t, domain.APIKeyStatusActive, result.APIKey.Status)
				assert.Equal(t, 100, result.APIKey.RateLimit)
			},
		},
		{
			name:     "nil scopes become empty slice",
			repo:     &mockRepo{},
			clientID: uuid.New(),
			keyName:  "nil-scopes",
			scopes:   nil,
			check: func(t *testing.T, result *CreateResult) {
				assert.NotNil(t, result.APIKey.Scopes)
				assert.Empty(t, result.APIKey.Scopes)
			},
		},
		{
			name:     "with expiration",
			repo:     &mockRepo{},
			clientID: uuid.New(),
			keyName:  "expiring-key",
			expiresAt: func() *time.Time {
				t := time.Now().Add(24 * time.Hour)
				return &t
			}(),
			check: func(t *testing.T, result *CreateResult) {
				assert.NotNil(t, result.APIKey.ExpiresAt)
			},
		},
		{
			name: "hash error",
			repo: &mockRepo{},
			hasher: &mockHasher{
				hashFn: func(_ string) (string, error) {
					return "", fmt.Errorf("hash failed")
				},
			},
			clientID: uuid.New(),
			keyName:  "fail-hash",
			wantErr:  true,
		},
		{
			name: "repo create error",
			repo: &mockRepo{
				createFn: func(_ context.Context, _ *domain.APIKey) (*domain.APIKey, error) {
					return nil, fmt.Errorf("db error")
				},
			},
			clientID: uuid.New(),
			keyName:  "fail-create",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := tt.hasher
			if hasher == nil {
				hasher = &mockHasher{}
			}
			svc := NewService(tt.repo, hasher, nil, zap.NewNop(), audit.NopLogger{})

			result, err := svc.CreateAPIKey(context.Background(), tt.clientID, tt.keyName, tt.scopes, tt.rateLimit, tt.expiresAt)
			if tt.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// --- ValidateAPIKey ---

func TestService_ValidateAPIKey(t *testing.T) {
	tests := []struct {
		name    string
		repo    *mockRepo
		hasher  *mockHasher
		key     string
		wantErr error
	}{
		{
			name: "success - active key",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					k := testAPIKey(uuid.New())
					k.RateLimit = 0 // no rate limit to skip Redis
					return k, nil
				},
			},
			key: "qf_ak_test",
		},
		{
			name: "not found",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					return nil, domain.ErrAPIKeyNotFound
				},
			},
			key:     "qf_ak_nonexistent",
			wantErr: domain.ErrAPIKeyNotFound,
		},
		{
			name: "revoked key",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					k := testAPIKey(uuid.New())
					k.Status = domain.APIKeyStatusRevoked
					return k, nil
				},
			},
			key:     "qf_ak_revoked",
			wantErr: domain.ErrAPIKeyRevoked,
		},
		{
			name: "expired key",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					k := testAPIKey(uuid.New())
					past := time.Now().Add(-1 * time.Hour)
					k.ExpiresAt = &past
					return k, nil
				},
			},
			key:     "qf_ak_expired",
			wantErr: domain.ErrAPIKeyExpired,
		},
		{
			name: "hash error",
			hasher: &mockHasher{
				hashFn: func(_ string) (string, error) {
					return "", fmt.Errorf("hash error")
				},
			},
			repo:    &mockRepo{},
			key:     "qf_ak_hash_fail",
			wantErr: errors.New("validate api key"),
		},
		{
			name: "repo error (non-not-found)",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					return nil, fmt.Errorf("db connection failed")
				},
			},
			key:     "qf_ak_db_fail",
			wantErr: errors.New("validate api key"),
		},
		{
			name: "update last_used_at failure is non-fatal",
			repo: &mockRepo{
				findByKeyHashFn: func(_ context.Context, _ string) (*domain.APIKey, error) {
					k := testAPIKey(uuid.New())
					k.RateLimit = 0
					return k, nil
				},
				updateLastUsedFn: func(_ context.Context, _ uuid.UUID, _ time.Time) error {
					return fmt.Errorf("redis timeout")
				},
			},
			key: "qf_ak_last_used_fail",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := tt.hasher
			if hasher == nil {
				hasher = &mockHasher{}
			}
			svc := NewService(tt.repo, hasher, nil, zap.NewNop(), audit.NopLogger{})

			key, _, err := svc.ValidateAPIKey(context.Background(), tt.key)
			if tt.wantErr != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErr, domain.ErrAPIKeyNotFound) ||
					errors.Is(tt.wantErr, domain.ErrAPIKeyRevoked) ||
					errors.Is(tt.wantErr, domain.ErrAPIKeyExpired) {
					assert.ErrorIs(t, err, tt.wantErr)
				}
				return
			}
			require.NoError(t, err)
			assert.NotNil(t, key)
			assert.Equal(t, domain.APIKeyStatusActive, key.Status)
		})
	}
}

// --- RotateKey ---

func TestService_RotateKey(t *testing.T) {
	tests := []struct {
		name    string
		repo    *mockRepo
		hasher  *mockHasher
		keyID   uuid.UUID
		wantErr error
		check   func(t *testing.T, result *RotateResult)
	}{
		{
			name:  "success",
			repo:  &mockRepo{},
			keyID: uuid.New(),
			check: func(t *testing.T, result *RotateResult) {
				assert.Contains(t, result.PlaintextKey, apiKeyPrefix)
				assert.NotNil(t, result.APIKey)
				assert.True(t, result.GracePeriodEnds.After(time.Now()))
				// Grace period should be ~24h from now.
				assert.WithinDuration(t, time.Now().Add(gracePeriodDuration), result.GracePeriodEnds, 5*time.Second)
			},
		},
		{
			name: "not found",
			repo: &mockRepo{
				findByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.APIKey, error) {
					return nil, domain.ErrAPIKeyNotFound
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyNotFound,
		},
		{
			name: "revoked key cannot be rotated",
			repo: &mockRepo{
				findByIDFn: func(_ context.Context, id uuid.UUID) (*domain.APIKey, error) {
					k := testAPIKey(id)
					k.Status = domain.APIKeyStatusRevoked
					return k, nil
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyRevoked,
		},
		{
			name: "hash error during rotation",
			hasher: &mockHasher{
				hashFn: func(_ string) (string, error) {
					return "", fmt.Errorf("hash failed")
				},
			},
			repo:    &mockRepo{},
			keyID:   uuid.New(),
			wantErr: errors.New("rotate key"),
		},
		{
			name: "repo rotate error",
			repo: &mockRepo{
				rotateKeyFn: func(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
					return fmt.Errorf("db error")
				},
			},
			keyID:   uuid.New(),
			wantErr: errors.New("rotate key"),
		},
		{
			name: "repo rotate not found",
			repo: &mockRepo{
				rotateKeyFn: func(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
					return domain.ErrAPIKeyNotFound
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hasher := tt.hasher
			if hasher == nil {
				hasher = &mockHasher{}
			}
			svc := NewService(tt.repo, hasher, nil, zap.NewNop(), audit.NopLogger{})

			result, err := svc.RotateKey(context.Background(), tt.keyID)
			if tt.wantErr != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErr, domain.ErrAPIKeyNotFound) ||
					errors.Is(tt.wantErr, domain.ErrAPIKeyRevoked) {
					assert.ErrorIs(t, err, tt.wantErr)
				}
				return
			}
			require.NoError(t, err)
			if tt.check != nil {
				tt.check(t, result)
			}
		})
	}
}

// --- RevokeKey ---

func TestService_RevokeKey(t *testing.T) {
	tests := []struct {
		name    string
		repo    *mockRepo
		keyID   uuid.UUID
		wantErr error
	}{
		{
			name:  "success",
			repo:  &mockRepo{},
			keyID: uuid.New(),
		},
		{
			name: "not found",
			repo: &mockRepo{
				findByIDFn: func(_ context.Context, _ uuid.UUID) (*domain.APIKey, error) {
					return nil, domain.ErrAPIKeyNotFound
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyNotFound,
		},
		{
			name: "already revoked",
			repo: &mockRepo{
				findByIDFn: func(_ context.Context, id uuid.UUID) (*domain.APIKey, error) {
					k := testAPIKey(id)
					k.Status = domain.APIKeyStatusRevoked
					return k, nil
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyRevoked,
		},
		{
			name: "repo revoke error",
			repo: &mockRepo{
				revokeFn: func(_ context.Context, _ uuid.UUID) error {
					return fmt.Errorf("db error")
				},
			},
			keyID:   uuid.New(),
			wantErr: errors.New("revoke key"),
		},
		{
			name: "repo revoke not found",
			repo: &mockRepo{
				revokeFn: func(_ context.Context, _ uuid.UUID) error {
					return domain.ErrAPIKeyNotFound
				},
			},
			keyID:   uuid.New(),
			wantErr: domain.ErrAPIKeyNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := newTestService(tt.repo)

			err := svc.RevokeKey(context.Background(), tt.keyID)
			if tt.wantErr != nil {
				require.Error(t, err)
				if errors.Is(tt.wantErr, domain.ErrAPIKeyNotFound) ||
					errors.Is(tt.wantErr, domain.ErrAPIKeyRevoked) {
					assert.ErrorIs(t, err, tt.wantErr)
				}
				return
			}
			require.NoError(t, err)
		})
	}
}

// --- checkRateLimit ---

func TestService_CheckRateLimit_NoLimit(t *testing.T) {
	svc := newTestService(&mockRepo{})

	info, err := svc.checkRateLimit(context.Background(), "test-key", 0)
	require.NoError(t, err)
	assert.Equal(t, 0, info.Limit)
}

func TestService_CheckRateLimit_NegativeLimit(t *testing.T) {
	svc := newTestService(&mockRepo{})

	info, err := svc.checkRateLimit(context.Background(), "test-key", -1)
	require.NoError(t, err)
	assert.Equal(t, 0, info.Limit)
}

// --- Domain type tests ---

func TestAPIKey_IsExpired(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:      "nil expiration - not expired",
			expiresAt: nil,
			want:      false,
		},
		{
			name: "future expiration - not expired",
			expiresAt: func() *time.Time {
				t := time.Now().Add(1 * time.Hour)
				return &t
			}(),
			want: false,
		},
		{
			name: "past expiration - expired",
			expiresAt: func() *time.Time {
				t := time.Now().Add(-1 * time.Hour)
				return &t
			}(),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &domain.APIKey{ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.want, key.IsExpired())
		})
	}
}

func TestAPIKey_IsActive(t *testing.T) {
	tests := []struct {
		name      string
		status    string
		expiresAt *time.Time
		want      bool
	}{
		{
			name:   "active status, no expiry",
			status: domain.APIKeyStatusActive,
			want:   true,
		},
		{
			name:   "revoked status",
			status: domain.APIKeyStatusRevoked,
			want:   false,
		},
		{
			name:   "active but expired",
			status: domain.APIKeyStatusActive,
			expiresAt: func() *time.Time {
				t := time.Now().Add(-1 * time.Hour)
				return &t
			}(),
			want: false,
		},
		{
			name:   "active with future expiry",
			status: domain.APIKeyStatusActive,
			expiresAt: func() *time.Time {
				t := time.Now().Add(1 * time.Hour)
				return &t
			}(),
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := &domain.APIKey{Status: tt.status, ExpiresAt: tt.expiresAt}
			assert.Equal(t, tt.want, key.IsActive())
		})
	}
}

// --- NewService ---

func TestNewService(t *testing.T) {
	repo := &mockRepo{}
	hasher := &mockHasher{}
	rdb := redis.NewClient(&redis.Options{Addr: "localhost:6379"})
	logger := zap.NewNop()
	auditor := audit.NopLogger{}

	svc := NewService(repo, hasher, rdb, logger, auditor)
	assert.NotNil(t, svc)
	assert.Equal(t, repo, svc.repo)
	assert.Equal(t, hasher, svc.hasher)
	assert.Equal(t, rdb, svc.rdb)
	assert.Equal(t, logger, svc.logger)

	_ = rdb.Close()
}

// --- isNotFound ---

func TestIsNotFound(t *testing.T) {
	assert.True(t, isNotFound(domain.ErrAPIKeyNotFound))
	assert.True(t, isNotFound(fmt.Errorf("wrapped: %w", domain.ErrAPIKeyNotFound)))
	assert.False(t, isNotFound(fmt.Errorf("some other error")))
	assert.False(t, isNotFound(domain.ErrAPIKeyRevoked))
}
