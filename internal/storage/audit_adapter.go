package storage

import (
	"context"

	"github.com/qf-studio/auth-service/internal/audit"
)

// AuditRepositoryAdapter wraps PostgresAuditRepository to satisfy audit.Repository.
type AuditRepositoryAdapter struct {
	repo *PostgresAuditRepository
}

// NewAuditRepositoryAdapter creates an adapter that bridges audit.Repository to
// the PostgresAuditRepository.
func NewAuditRepositoryAdapter(repo *PostgresAuditRepository) *AuditRepositoryAdapter {
	return &AuditRepositoryAdapter{repo: repo}
}

// Insert converts an audit.RepositoryEntry to a storage.AuditEntry and persists it.
func (a *AuditRepositoryAdapter) Insert(ctx context.Context, entry *audit.RepositoryEntry) error {
	return a.repo.Insert(ctx, &AuditEntry{
		EventType: entry.EventType,
		ActorID:   entry.ActorID,
		TargetID:  entry.TargetID,
		IP:        entry.IP,
		Severity:  entry.Severity,
		Metadata:  entry.Metadata,
		CreatedAt: entry.CreatedAt,
	})
}
