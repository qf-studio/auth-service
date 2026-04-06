package admin

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/metrics"
	"github.com/qf-studio/auth-service/internal/storage"
)

// --- Mock AuditRepository ---

type mockAuditRepo struct {
	insertFn              func(ctx context.Context, entry *storage.AuditEntry) error
	listFn                func(ctx context.Context, limit, offset int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error)
	countByTypeFn         func(ctx context.Context, eventType string, since time.Time) (int64, error)
	countByTypesFn        func(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
	topTargetedAccountsFn func(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error)
	topSourceIPsFn        func(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error)
	recentByTypesFn       func(ctx context.Context, eventTypes []string, limit int) ([]*storage.AuditEntry, error)
	distinctActorsFn      func(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
}

func (m *mockAuditRepo) Insert(ctx context.Context, entry *storage.AuditEntry) error {
	if m.insertFn != nil {
		return m.insertFn(ctx, entry)
	}
	return nil
}

func (m *mockAuditRepo) List(ctx context.Context, limit, offset int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error) {
	if m.listFn != nil {
		return m.listFn(ctx, limit, offset, filter)
	}
	return nil, 0, nil
}

func (m *mockAuditRepo) CountByType(ctx context.Context, eventType string, since time.Time) (int64, error) {
	if m.countByTypeFn != nil {
		return m.countByTypeFn(ctx, eventType, since)
	}
	return 0, nil
}

func (m *mockAuditRepo) CountByTypes(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	if m.countByTypesFn != nil {
		return m.countByTypesFn(ctx, eventTypes, since)
	}
	return 0, nil
}

func (m *mockAuditRepo) TopTargetedAccounts(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error) {
	if m.topTargetedAccountsFn != nil {
		return m.topTargetedAccountsFn(ctx, eventType, since, limit)
	}
	return nil, nil
}

func (m *mockAuditRepo) TopSourceIPs(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error) {
	if m.topSourceIPsFn != nil {
		return m.topSourceIPsFn(ctx, eventType, since, limit)
	}
	return nil, nil
}

func (m *mockAuditRepo) RecentByTypes(ctx context.Context, eventTypes []string, limit int) ([]*storage.AuditEntry, error) {
	if m.recentByTypesFn != nil {
		return m.recentByTypesFn(ctx, eventTypes, limit)
	}
	return nil, nil
}

func (m *mockAuditRepo) DistinctActors(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	if m.distinctActorsFn != nil {
		return m.distinctActorsFn(ctx, eventTypes, since)
	}
	return 0, nil
}

// --- Mock DashboardRepository ---

type mockDashboardRepo struct {
	countUsersFn           func(ctx context.Context) (int, error)
	countLockedUsersFn     func(ctx context.Context) (int, error)
	countClientsFn         func(ctx context.Context) (int, error)
	countActiveSessionsFn  func(ctx context.Context) (int64, error)
	countMFAEnabledUsersFn func(ctx context.Context) (int64, error)
}

func (m *mockDashboardRepo) CountUsers(ctx context.Context) (int, error) {
	if m.countUsersFn != nil {
		return m.countUsersFn(ctx)
	}
	return 10, nil
}

func (m *mockDashboardRepo) CountLockedUsers(ctx context.Context) (int, error) {
	if m.countLockedUsersFn != nil {
		return m.countLockedUsersFn(ctx)
	}
	return 0, nil
}

func (m *mockDashboardRepo) CountClients(ctx context.Context) (int, error) {
	if m.countClientsFn != nil {
		return m.countClientsFn(ctx)
	}
	return 5, nil
}

func (m *mockDashboardRepo) CountActiveSessions(ctx context.Context) (int64, error) {
	if m.countActiveSessionsFn != nil {
		return m.countActiveSessionsFn(ctx)
	}
	return 42, nil
}

func (m *mockDashboardRepo) CountMFAEnabledUsers(ctx context.Context) (int64, error) {
	if m.countMFAEnabledUsersFn != nil {
		return m.countMFAEnabledUsersFn(ctx)
	}
	return 3, nil
}

// --- Helper to build service ---

func newTestDashboardService(auditRepo storage.AuditRepository, dashRepo storage.DashboardRepository) *DashboardService {
	mc := metrics.New()
	hs := health.NewService()
	return NewDashboardService(auditRepo, dashRepo, mc, hs, zap.NewNop())
}

// --- Tests ---

func TestDashboardService_Overview(t *testing.T) {
	auditRepo := &mockAuditRepo{
		distinctActorsFn: func(_ context.Context, _ []string, _ time.Time) (int64, error) {
			return 7, nil
		},
	}
	dashRepo := &mockDashboardRepo{}
	svc := newTestDashboardService(auditRepo, dashRepo)

	result, err := svc.Overview(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(42), result.ActiveSessions)
	assert.Equal(t, int64(7), result.ActiveUsers24h)
	assert.Equal(t, 10, result.TotalUsers)
	assert.Equal(t, 5, result.TotalClients)
	assert.Equal(t, 30.0, result.MFAAdoptionRate) // 3/10 * 100
	assert.Equal(t, "healthy", result.SystemHealth)
	assert.Equal(t, float64(100), result.AuthSuccessRate) // no auth events => 100%
}

func TestDashboardService_Overview_SessionCountError(t *testing.T) {
	auditRepo := &mockAuditRepo{}
	dashRepo := &mockDashboardRepo{
		countActiveSessionsFn: func(_ context.Context) (int64, error) {
			return 0, errors.New("db error")
		},
	}
	svc := newTestDashboardService(auditRepo, dashRepo)

	_, err := svc.Overview(context.Background())
	require.Error(t, err)
}

func TestDashboardService_Overview_ZeroUsers(t *testing.T) {
	auditRepo := &mockAuditRepo{}
	dashRepo := &mockDashboardRepo{
		countUsersFn: func(_ context.Context) (int, error) { return 0, nil },
	}
	svc := newTestDashboardService(auditRepo, dashRepo)

	result, err := svc.Overview(context.Background())
	require.NoError(t, err)
	assert.Equal(t, float64(0), result.MFAAdoptionRate) // no division by zero
}

func TestDashboardService_Security(t *testing.T) {
	now := time.Now().UTC()
	auditRepo := &mockAuditRepo{
		countByTypeFn: func(_ context.Context, _ string, _ time.Time) (int64, error) {
			return 15, nil
		},
		topTargetedAccountsFn: func(_ context.Context, _ string, _ time.Time, _ int) ([]storage.AuditCount, error) {
			return []storage.AuditCount{
				{ID: "user-1", Count: 10},
				{ID: "user-2", Count: 5},
			}, nil
		},
		topSourceIPsFn: func(_ context.Context, _ string, _ time.Time, _ int) ([]storage.AuditCount, error) {
			return []storage.AuditCount{
				{ID: "192.168.1.1", Count: 8},
			}, nil
		},
		recentByTypesFn: func(_ context.Context, _ []string, _ int) ([]*storage.AuditEntry, error) {
			return []*storage.AuditEntry{
				{ID: "evt-1", EventType: "login_failure", CreatedAt: now},
			}, nil
		},
	}
	dashRepo := &mockDashboardRepo{
		countLockedUsersFn: func(_ context.Context) (int, error) { return 2, nil },
	}
	svc := newTestDashboardService(auditRepo, dashRepo)

	result, err := svc.Security(context.Background())
	require.NoError(t, err)

	assert.Equal(t, int64(15), result.FailedLogins24h)
	assert.Len(t, result.TopTargetedAccounts, 2)
	assert.Equal(t, "user-1", result.TopTargetedAccounts[0].ID)
	assert.Len(t, result.TopSourceIPs, 1)
	assert.Equal(t, 2, result.LockedAccounts)
	assert.Len(t, result.RecentSecurityEvents, 1)
}

func TestDashboardService_Security_FailedCountError(t *testing.T) {
	auditRepo := &mockAuditRepo{
		countByTypeFn: func(_ context.Context, _ string, _ time.Time) (int64, error) {
			return 0, errors.New("db error")
		},
	}
	dashRepo := &mockDashboardRepo{}
	svc := newTestDashboardService(auditRepo, dashRepo)

	_, err := svc.Security(context.Background())
	require.Error(t, err)
}

func TestDashboardService_ListAuditLogs(t *testing.T) {
	now := time.Now().UTC()
	auditRepo := &mockAuditRepo{
		listFn: func(_ context.Context, limit, offset int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error) {
			assert.Equal(t, 20, limit)
			assert.Equal(t, 0, offset)
			assert.Equal(t, "login_failure", filter.Action)
			return []*storage.AuditEntry{
				{ID: "log-1", EventType: "login_failure", ActorID: "user-1", CreatedAt: now},
				{ID: "log-2", EventType: "login_failure", ActorID: "user-2", CreatedAt: now},
			}, 2, nil
		},
	}
	dashRepo := &mockDashboardRepo{}
	svc := newTestDashboardService(auditRepo, dashRepo)

	result, err := svc.ListAuditLogs(context.Background(), 1, 20, "login_failure", "", "", nil, nil)
	require.NoError(t, err)

	assert.Equal(t, 2, result.Total)
	assert.Equal(t, 1, result.Page)
	assert.Equal(t, 20, result.PerPage)
	assert.Len(t, result.Entries, 2)
	assert.Equal(t, "log-1", result.Entries[0].ID)
}

func TestDashboardService_ListAuditLogs_WithDateFilter(t *testing.T) {
	start := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 4, 6, 0, 0, 0, 0, time.UTC)
	auditRepo := &mockAuditRepo{
		listFn: func(_ context.Context, _ int, _ int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error) {
			require.NotNil(t, filter.StartDate)
			require.NotNil(t, filter.EndDate)
			assert.Equal(t, start, *filter.StartDate)
			assert.Equal(t, end, *filter.EndDate)
			return nil, 0, nil
		},
	}
	dashRepo := &mockDashboardRepo{}
	svc := newTestDashboardService(auditRepo, dashRepo)

	result, err := svc.ListAuditLogs(context.Background(), 1, 20, "", "", "", &start, &end)
	require.NoError(t, err)
	assert.Equal(t, 0, result.Total)
}

func TestDashboardService_ListAuditLogs_Error(t *testing.T) {
	auditRepo := &mockAuditRepo{
		listFn: func(_ context.Context, _ int, _ int, _ storage.AuditLogFilter) ([]*storage.AuditEntry, int, error) {
			return nil, 0, errors.New("db error")
		},
	}
	dashRepo := &mockDashboardRepo{}
	svc := newTestDashboardService(auditRepo, dashRepo)

	_, err := svc.ListAuditLogs(context.Background(), 1, 20, "", "", "", nil, nil)
	require.Error(t, err)
}
