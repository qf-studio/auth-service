package mocks

import (
	"context"

	"github.com/google/uuid"

	"github.com/qf-studio/auth-service/internal/storage"
)

// MockAuditReadRepository is a configurable mock for storage.AuditReadRepository.
type MockAuditReadRepository struct {
	ListByTargetIDFn func(ctx context.Context, tenantID uuid.UUID, targetID string, limit, offset int) ([]storage.AuditEntry, int, error)
}

// ListByTargetID delegates to ListByTargetIDFn.
func (m *MockAuditReadRepository) ListByTargetID(ctx context.Context, tenantID uuid.UUID, targetID string, limit, offset int) ([]storage.AuditEntry, int, error) {
	return m.ListByTargetIDFn(ctx, tenantID, targetID, limit, offset)
}
