package mocks

import (
	"context"
	"time"

	"github.com/qf-studio/auth-service/internal/storage"
)

// MockAuditRepository is a configurable mock for storage.AuditRepository.
type MockAuditRepository struct {
	InsertFn              func(ctx context.Context, entry *storage.AuditEntry) error
	ListFn                func(ctx context.Context, limit, offset int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error)
	CountByTypeFn         func(ctx context.Context, eventType string, since time.Time) (int64, error)
	CountByTypesFn        func(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
	TopTargetedAccountsFn func(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error)
	TopSourceIPsFn        func(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error)
	RecentByTypesFn       func(ctx context.Context, eventTypes []string, limit int) ([]*storage.AuditEntry, error)
	DistinctActorsFn      func(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
}

// Insert delegates to InsertFn.
func (m *MockAuditRepository) Insert(ctx context.Context, entry *storage.AuditEntry) error {
	return m.InsertFn(ctx, entry)
}

// List delegates to ListFn.
func (m *MockAuditRepository) List(ctx context.Context, limit, offset int, filter storage.AuditLogFilter) ([]*storage.AuditEntry, int, error) {
	return m.ListFn(ctx, limit, offset, filter)
}

// CountByType delegates to CountByTypeFn.
func (m *MockAuditRepository) CountByType(ctx context.Context, eventType string, since time.Time) (int64, error) {
	return m.CountByTypeFn(ctx, eventType, since)
}

// CountByTypes delegates to CountByTypesFn.
func (m *MockAuditRepository) CountByTypes(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	return m.CountByTypesFn(ctx, eventTypes, since)
}

// TopTargetedAccounts delegates to TopTargetedAccountsFn.
func (m *MockAuditRepository) TopTargetedAccounts(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error) {
	return m.TopTargetedAccountsFn(ctx, eventType, since, limit)
}

// TopSourceIPs delegates to TopSourceIPsFn.
func (m *MockAuditRepository) TopSourceIPs(ctx context.Context, eventType string, since time.Time, limit int) ([]storage.AuditCount, error) {
	return m.TopSourceIPsFn(ctx, eventType, since, limit)
}

// RecentByTypes delegates to RecentByTypesFn.
func (m *MockAuditRepository) RecentByTypes(ctx context.Context, eventTypes []string, limit int) ([]*storage.AuditEntry, error) {
	return m.RecentByTypesFn(ctx, eventTypes, limit)
}

// DistinctActors delegates to DistinctActorsFn.
func (m *MockAuditRepository) DistinctActors(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	return m.DistinctActorsFn(ctx, eventTypes, since)
}
