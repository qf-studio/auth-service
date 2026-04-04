package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/audit"
)

// AuditRepository defines the persistence operations for audit events.
type AuditRepository interface {
	// Insert persists a single audit event (append-only).
	Insert(ctx context.Context, event *audit.AuditEvent) error

	// List retrieves audit events with pagination, ordered by occurred_at descending.
	List(ctx context.Context, filter AuditFilter) ([]audit.AuditEvent, int, error)
}

// AuditFilter controls pagination and filtering for audit log queries.
type AuditFilter struct {
	// EventType filters by event type (exact match). Empty means no filter.
	EventType string

	// SubjectID filters by the actor's ID. Empty means no filter.
	SubjectID string

	// ResourceType filters by resource type. Empty means no filter.
	ResourceType string

	// ResourceID filters by resource ID. Empty means no filter.
	ResourceID string

	// From filters events on or after this time. Zero means no lower bound.
	From time.Time

	// To filters events before this time. Zero means no upper bound.
	To time.Time

	// Limit is the maximum number of results to return. Default 50, max 200.
	Limit int

	// Offset is the number of results to skip.
	Offset int
}

// PostgresAuditRepository implements AuditRepository using pgx.
type PostgresAuditRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditRepository creates a new PostgreSQL-backed audit repository.
func NewPostgresAuditRepository(pool *pgxpool.Pool) *PostgresAuditRepository {
	return &PostgresAuditRepository{pool: pool}
}

const auditInsertQuery = `
	INSERT INTO audit_logs (
		id, event_type, outcome, occurred_at,
		subject_id, subject_type, resource_type, resource_id,
		action, source_ip, user_agent, correlation_id,
		component, metadata
	) VALUES (
		$1, $2, $3, $4,
		$5, $6, $7, $8,
		$9, $10, $11, $12,
		$13, $14
	)`

// Insert persists a single audit event to the audit_logs table.
func (r *PostgresAuditRepository) Insert(ctx context.Context, event *audit.AuditEvent) error {
	metaJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx, auditInsertQuery,
		event.ID, string(event.EventType), string(event.Outcome), event.Timestamp,
		event.SubjectID, event.SubjectType, event.ResourceType, event.ResourceID,
		event.Action, event.SourceIP, event.UserAgent, event.CorrelationID,
		event.Component, metaJSON,
	)
	if err != nil {
		return fmt.Errorf("insert audit event: %w", err)
	}

	return nil
}

// List retrieves audit events matching the filter with pagination.
// Returns events (descending by time), total count, and any error.
func (r *PostgresAuditRepository) List(ctx context.Context, filter AuditFilter) ([]audit.AuditEvent, int, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	// Build WHERE clause dynamically.
	where := "WHERE 1=1"
	args := []any{}
	argIdx := 1

	if filter.EventType != "" {
		where += fmt.Sprintf(" AND event_type = $%d", argIdx)
		args = append(args, filter.EventType)
		argIdx++
	}
	if filter.SubjectID != "" {
		where += fmt.Sprintf(" AND subject_id = $%d", argIdx)
		args = append(args, filter.SubjectID)
		argIdx++
	}
	if filter.ResourceType != "" {
		where += fmt.Sprintf(" AND resource_type = $%d", argIdx)
		args = append(args, filter.ResourceType)
		argIdx++
	}
	if filter.ResourceID != "" {
		where += fmt.Sprintf(" AND resource_id = $%d", argIdx)
		args = append(args, filter.ResourceID)
		argIdx++
	}
	if !filter.From.IsZero() {
		where += fmt.Sprintf(" AND occurred_at >= $%d", argIdx)
		args = append(args, filter.From)
		argIdx++
	}
	if !filter.To.IsZero() {
		where += fmt.Sprintf(" AND occurred_at < $%d", argIdx)
		args = append(args, filter.To)
		argIdx++
	}

	// Count query.
	countQuery := "SELECT COUNT(*) FROM audit_logs " + where
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	// Data query with pagination.
	dataQuery := fmt.Sprintf(`
		SELECT id, event_type, outcome, occurred_at,
		       subject_id, subject_type, resource_type, resource_id,
		       action, source_ip, user_agent, correlation_id,
		       component, metadata
		FROM audit_logs
		%s
		ORDER BY occurred_at DESC
		LIMIT $%d OFFSET $%d`,
		where, argIdx, argIdx+1)

	args = append(args, limit, filter.Offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit events: %w", err)
	}
	defer rows.Close()

	var events []audit.AuditEvent
	for rows.Next() {
		var e audit.AuditEvent
		var metaJSON []byte
		err := rows.Scan(
			&e.ID, &e.EventType, &e.Outcome, &e.Timestamp,
			&e.SubjectID, &e.SubjectType, &e.ResourceType, &e.ResourceID,
			&e.Action, &e.SourceIP, &e.UserAgent, &e.CorrelationID,
			&e.Component, &metaJSON,
		)
		if err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}
		if len(metaJSON) > 0 {
			e.Metadata = make(map[string]string)
			if err := json.Unmarshal(metaJSON, &e.Metadata); err != nil {
				return nil, 0, fmt.Errorf("unmarshal audit metadata: %w", err)
			}
		}
		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit events: %w", err)
	}

	return events, total, nil
}
