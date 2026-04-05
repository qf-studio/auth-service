package mocks

import "context"

// MockRedisMFAStore is a configurable mock for storage.RedisMFAStore.
type MockRedisMFAStore struct {
	StoreMFATokenFn      func(ctx context.Context, token, userID string) error
	ConsumeMFATokenFn    func(ctx context.Context, token string) (string, error)
	RecordFailedAttemptFn func(ctx context.Context, userID string) (int, error)
	GetFailedAttemptsFn  func(ctx context.Context, userID string) (int, error)
	ClearFailedAttemptsFn func(ctx context.Context, userID string) error
}

// StoreMFAToken delegates to StoreMFATokenFn.
func (m *MockRedisMFAStore) StoreMFAToken(ctx context.Context, token, userID string) error {
	return m.StoreMFATokenFn(ctx, token, userID)
}

// ConsumeMFAToken delegates to ConsumeMFATokenFn.
func (m *MockRedisMFAStore) ConsumeMFAToken(ctx context.Context, token string) (string, error) {
	return m.ConsumeMFATokenFn(ctx, token)
}

// RecordFailedAttempt delegates to RecordFailedAttemptFn.
func (m *MockRedisMFAStore) RecordFailedAttempt(ctx context.Context, userID string) (int, error) {
	return m.RecordFailedAttemptFn(ctx, userID)
}

// GetFailedAttempts delegates to GetFailedAttemptsFn.
func (m *MockRedisMFAStore) GetFailedAttempts(ctx context.Context, userID string) (int, error) {
	return m.GetFailedAttemptsFn(ctx, userID)
}

// ClearFailedAttempts delegates to ClearFailedAttemptsFn.
func (m *MockRedisMFAStore) ClearFailedAttempts(ctx context.Context, userID string) error {
	return m.ClearFailedAttemptsFn(ctx, userID)
}
