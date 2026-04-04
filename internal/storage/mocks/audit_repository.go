package mocks

import (
	"context"

	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/storage"
)

// MockAuditRepository is a configurable mock for storage.AuditRepository.
type MockAuditRepository struct {
	InsertFn func(ctx context.Context, event *audit.AuditEvent) error
	ListFn   func(ctx context.Context, filter storage.AuditFilter) ([]audit.AuditEvent, int, error)
}

// Insert delegates to InsertFn.
func (m *MockAuditRepository) Insert(ctx context.Context, event *audit.AuditEvent) error {
	return m.InsertFn(ctx, event)
}

// List delegates to ListFn.
func (m *MockAuditRepository) List(ctx context.Context, filter storage.AuditFilter) ([]audit.AuditEvent, int, error) {
	return m.ListFn(ctx, filter)
}
