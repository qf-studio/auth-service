package oauth

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// memStateStore is an in-memory StateStore for testing.
type memStateStore struct {
	mu   sync.Mutex
	data map[string][]byte
}

func newMemStateStore() *memStateStore {
	return &memStateStore{data: make(map[string][]byte)}
}

func (s *memStateStore) StoreOAuthState(_ context.Context, key string, data []byte, _ time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = data
	return nil
}

func (s *memStateStore) ConsumeOAuthState(_ context.Context, key string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, ok := s.data[key]
	if !ok {
		return nil, fmt.Errorf("not found")
	}
	delete(s.data, key)
	return data, nil
}

func TestStateManager_GenerateAndValidate(t *testing.T) {
	store := newMemStateStore()
	sm := NewStateManager("test-secret-key", store)
	ctx := context.Background()

	stateToken, err := sm.GenerateState(ctx, "google", "verifier-123")
	require.NoError(t, err)
	assert.NotEmpty(t, stateToken)
	assert.Contains(t, stateToken, ".")

	provider, verifier, err := sm.ValidateState(ctx, stateToken)
	require.NoError(t, err)
	assert.Equal(t, "google", provider)
	assert.Equal(t, "verifier-123", verifier)
}

func TestStateManager_ReplayPrevention(t *testing.T) {
	store := newMemStateStore()
	sm := NewStateManager("test-secret-key", store)
	ctx := context.Background()

	stateToken, err := sm.GenerateState(ctx, "github", "verifier-456")
	require.NoError(t, err)

	// First validation succeeds.
	_, _, err = sm.ValidateState(ctx, stateToken)
	require.NoError(t, err)

	// Second validation fails (consumed).
	_, _, err = sm.ValidateState(ctx, stateToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "consume state")
}

func TestStateManager_InvalidSignature(t *testing.T) {
	store := newMemStateStore()
	sm := NewStateManager("test-secret-key", store)
	ctx := context.Background()

	stateToken, err := sm.GenerateState(ctx, "google", "verifier-789")
	require.NoError(t, err)

	// Tamper with the signature.
	tampered := stateToken[:len(stateToken)-4] + "XXXX"
	_, _, err = sm.ValidateState(ctx, tampered)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state signature")
}

func TestStateManager_MalformedToken(t *testing.T) {
	store := newMemStateStore()
	sm := NewStateManager("test-secret-key", store)
	ctx := context.Background()

	_, _, err := sm.ValidateState(ctx, "no-dot-separator")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "malformed state token")
}

func TestStateManager_DifferentSecrets(t *testing.T) {
	store := newMemStateStore()
	sm1 := NewStateManager("secret-1", store)
	sm2 := NewStateManager("secret-2", store)
	ctx := context.Background()

	stateToken, err := sm1.GenerateState(ctx, "google", "verifier")
	require.NoError(t, err)

	// Validation with different secret fails.
	_, _, err = sm2.ValidateState(ctx, stateToken)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid state signature")
}
