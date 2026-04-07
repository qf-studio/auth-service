package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEntry represents a single audit log record returned by read queries.
type AuditEntry struct {
	ID        string            `json:"id"`
	TenantID  uuid.UUID         `json:"tenant_id"`
	EventType string            `json:"event_type"`
	ActorID   string            `json:"actor_id"`
	TargetID  string            `json:"target_id"`
	IP        string            `json:"ip"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// AuditReadRepository defines read-only queries for audit log entries.
type AuditReadRepository interface {
	// ListByTargetID returns audit events for a given target (e.g. user ID), newest first.
	ListByTargetID(ctx context.Context, tenantID uuid.UUID, targetID string, limit, offset int) ([]AuditEntry, int, error)
}

// PostgresAuditReadRepository implements AuditReadRepository using PostgreSQL.
type PostgresAuditReadRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditReadRepository creates a new PostgreSQL-backed audit read repository.
func NewPostgresAuditReadRepository(pool *pgxpool.Pool) *PostgresAuditReadRepository {
	return &PostgresAuditReadRepository{pool: pool}
}

// ListByTargetID returns audit events for the given target ID, ordered by created_at DESC.
func (r *PostgresAuditReadRepository) ListByTargetID(ctx context.Context, tenantID uuid.UUID, targetID string, limit, offset int) ([]AuditEntry, int, error) {
	// Count total matching entries.
	var total int
	countQ := `SELECT COUNT(*) FROM audit_logs WHERE target_id = $1 AND tenant_id = $2`
	if err := r.pool.QueryRow(ctx, countQ, targetID, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	// Fetch page.
	dataQ := `SELECT id, tenant_id, event_type, actor_id, target_id, ip, metadata, created_at
		FROM audit_logs WHERE target_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`
	rows, err := r.pool.Query(ctx, dataQ, targetID, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var entries []AuditEntry
	for rows.Next() {
		var e AuditEntry
		var metaJSON []byte
		if err := rows.Scan(&e.ID, &e.TenantID, &e.EventType, &e.ActorID, &e.TargetID, &e.IP, &metaJSON, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		if len(metaJSON) > 0 {
			e.Metadata = make(map[string]string)
			_ = json.Unmarshal(metaJSON, &e.Metadata)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit logs: %w", err)
	}

	return entries, total, nil
}
