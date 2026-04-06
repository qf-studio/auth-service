package mocks

import "context"

// MockDashboardRepository is a configurable mock for storage.DashboardRepository.
type MockDashboardRepository struct {
	CountUsersFn           func(ctx context.Context) (int, error)
	CountLockedUsersFn     func(ctx context.Context) (int, error)
	CountClientsFn         func(ctx context.Context) (int, error)
	CountActiveSessionsFn  func(ctx context.Context) (int64, error)
	CountMFAEnabledUsersFn func(ctx context.Context) (int64, error)
}

// CountUsers delegates to CountUsersFn.
func (m *MockDashboardRepository) CountUsers(ctx context.Context) (int, error) {
	return m.CountUsersFn(ctx)
}

// CountLockedUsers delegates to CountLockedUsersFn.
func (m *MockDashboardRepository) CountLockedUsers(ctx context.Context) (int, error) {
	return m.CountLockedUsersFn(ctx)
}

// CountClients delegates to CountClientsFn.
func (m *MockDashboardRepository) CountClients(ctx context.Context) (int, error) {
	return m.CountClientsFn(ctx)
}

// CountActiveSessions delegates to CountActiveSessionsFn.
func (m *MockDashboardRepository) CountActiveSessions(ctx context.Context) (int64, error) {
	return m.CountActiveSessionsFn(ctx)
}

// CountMFAEnabledUsers delegates to CountMFAEnabledUsersFn.
func (m *MockDashboardRepository) CountMFAEnabledUsers(ctx context.Context) (int64, error) {
	return m.CountMFAEnabledUsersFn(ctx)
}
