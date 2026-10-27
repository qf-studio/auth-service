package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/audit"
)

// PostgresAuditSink implements audit.Sink on the audit_logs table.
type PostgresAuditSink struct {
	pool *pgxpool.Pool
}

var _ audit.Sink = (*PostgresAuditSink)(nil)

// NewPostgresAuditSink creates a PostgreSQL-backed audit sink.
func NewPostgresAuditSink(pool *pgxpool.Pool) *PostgresAuditSink {
	return &PostgresAuditSink{pool: pool}
}

const insertAuditLogSQL = `INSERT INTO audit_logs
	(tenant_id, event_type, actor_id, target_id, ip, user_agent, metadata, created_at)
	VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`

// InsertBatch inserts all events in a single round trip and transaction: either
// every event of the batch is stored or none is.
func (r *PostgresAuditSink) InsertBatch(ctx context.Context, events []audit.Event) error {
	if len(events) == 0 {
		return nil
	}

	batch := &pgx.Batch{}
	for i := range events {
		ev := &events[i]
		meta := ev.Metadata
		if meta == nil {
			meta = map[string]string{}
		}
		metaJSON, err := json.Marshal(meta)
		if err != nil {
			return fmt.Errorf("marshal audit metadata: %w", err)
		}
		batch.Queue(insertAuditLogSQL,
			ev.TenantID, ev.Type, ev.ActorID, ev.TargetID, ev.IP, ev.UserAgent, metaJSON, ev.Timestamp)
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin audit batch: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	results := tx.SendBatch(ctx, batch)
	for range events {
		if _, err := results.Exec(); err != nil {
			_ = results.Close()
			return fmt.Errorf("insert audit log: %w", err)
		}
	}
	if err := results.Close(); err != nil {
		return fmt.Errorf("close audit batch: %w", err)
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit audit batch: %w", err)
	}
	return nil
}

// DeleteOlderThan removes audit rows (all tenants) created before cutoff.
func (r *PostgresAuditSink) DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx, `DELETE FROM audit_logs WHERE created_at < $1`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("delete expired audit logs: %w", err)
	}
	return tag.RowsAffected(), nil
}
