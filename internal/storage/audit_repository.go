package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditEntry represents a single row in the audit_logs table.
type AuditEntry struct {
	ID        string            `json:"id"`
	EventType string            `json:"event_type"`
	ActorID   string            `json:"actor_id"`
	TargetID  string            `json:"target_id"`
	IP        string            `json:"ip"`
	Severity  string            `json:"severity"`
	Metadata  map[string]string `json:"metadata"`
	CreatedAt time.Time         `json:"created_at"`
}

// AuditLogFilter specifies criteria for querying audit logs.
type AuditLogFilter struct {
	Action    string
	ActorID   string
	StartDate *time.Time
	EndDate   *time.Time
	Severity  string
}

// AuditCount holds an identifier and its occurrence count.
type AuditCount struct {
	ID    string `json:"id"`
	Count int64  `json:"count"`
}

// AuditRepository defines persistence operations for audit log entries.
type AuditRepository interface {
	Insert(ctx context.Context, entry *AuditEntry) error
	List(ctx context.Context, limit, offset int, filter AuditLogFilter) ([]*AuditEntry, int, error)
	CountByType(ctx context.Context, eventType string, since time.Time) (int64, error)
	CountByTypes(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
	TopTargetedAccounts(ctx context.Context, eventType string, since time.Time, limit int) ([]AuditCount, error)
	TopSourceIPs(ctx context.Context, eventType string, since time.Time, limit int) ([]AuditCount, error)
	RecentByTypes(ctx context.Context, eventTypes []string, limit int) ([]*AuditEntry, error)
	DistinctActors(ctx context.Context, eventTypes []string, since time.Time) (int64, error)
}

// PostgresAuditRepository implements AuditRepository with PostgreSQL.
type PostgresAuditRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditRepository creates a new PostgresAuditRepository.
func NewPostgresAuditRepository(pool *pgxpool.Pool) *PostgresAuditRepository {
	return &PostgresAuditRepository{pool: pool}
}

// Insert persists a single audit log entry.
func (r *PostgresAuditRepository) Insert(ctx context.Context, entry *AuditEntry) error {
	meta, err := json.Marshal(entry.Metadata)
	if err != nil {
		meta = []byte("{}")
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_logs (event_type, actor_id, target_id, ip, severity, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.EventType, entry.ActorID, entry.TargetID, entry.IP, entry.Severity, meta, entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// List returns paginated audit log entries matching the filter.
func (r *PostgresAuditRepository) List(ctx context.Context, limit, offset int, filter AuditLogFilter) ([]*AuditEntry, int, error) {
	where, args := buildAuditWhere(filter)

	// Count total matching rows.
	countQuery := "SELECT COUNT(*) FROM audit_logs" + where
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	// Fetch page.
	query := "SELECT id, event_type, actor_id, target_id, ip, severity, metadata, created_at FROM audit_logs" +
		where + " ORDER BY created_at DESC LIMIT $" + fmt.Sprintf("%d", len(args)+1) +
		" OFFSET $" + fmt.Sprintf("%d", len(args)+2)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var meta []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.ActorID, &e.TargetID, &e.IP, &e.Severity, &meta, &e.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log: %w", err)
		}
		e.Metadata = make(map[string]string)
		_ = json.Unmarshal(meta, &e.Metadata)
		entries = append(entries, e)
	}

	return entries, total, rows.Err()
}

// CountByType returns the number of events of the given type since the given time.
func (r *PostgresAuditRepository) CountByType(ctx context.Context, eventType string, since time.Time) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_logs WHERE event_type = $1 AND created_at >= $2",
		eventType, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count by type: %w", err)
	}
	return count, nil
}

// CountByTypes returns the number of events matching any of the given types since the given time.
func (r *PostgresAuditRepository) CountByTypes(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	if len(eventTypes) == 0 {
		return 0, nil
	}
	var count int64
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_logs WHERE event_type = ANY($1) AND created_at >= $2",
		eventTypes, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count by types: %w", err)
	}
	return count, nil
}

// TopTargetedAccounts returns the top N target IDs by occurrence count for the given event type.
func (r *PostgresAuditRepository) TopTargetedAccounts(ctx context.Context, eventType string, since time.Time, limit int) ([]AuditCount, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT target_id, COUNT(*) AS cnt
		 FROM audit_logs
		 WHERE event_type = $1 AND created_at >= $2 AND target_id != ''
		 GROUP BY target_id
		 ORDER BY cnt DESC
		 LIMIT $3`,
		eventType, since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("top targeted accounts: %w", err)
	}
	defer rows.Close()

	var results []AuditCount
	for rows.Next() {
		var ac AuditCount
		if err := rows.Scan(&ac.ID, &ac.Count); err != nil {
			return nil, fmt.Errorf("scan targeted account: %w", err)
		}
		results = append(results, ac)
	}
	return results, rows.Err()
}

// TopSourceIPs returns the top N IPs by occurrence count for the given event type.
func (r *PostgresAuditRepository) TopSourceIPs(ctx context.Context, eventType string, since time.Time, limit int) ([]AuditCount, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT ip, COUNT(*) AS cnt
		 FROM audit_logs
		 WHERE event_type = $1 AND created_at >= $2 AND ip != ''
		 GROUP BY ip
		 ORDER BY cnt DESC
		 LIMIT $3`,
		eventType, since, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("top source ips: %w", err)
	}
	defer rows.Close()

	var results []AuditCount
	for rows.Next() {
		var ac AuditCount
		if err := rows.Scan(&ac.ID, &ac.Count); err != nil {
			return nil, fmt.Errorf("scan source ip: %w", err)
		}
		results = append(results, ac)
	}
	return results, rows.Err()
}

// RecentByTypes returns the most recent N events matching any of the given types.
func (r *PostgresAuditRepository) RecentByTypes(ctx context.Context, eventTypes []string, limit int) ([]*AuditEntry, error) {
	if len(eventTypes) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, event_type, actor_id, target_id, ip, severity, metadata, created_at
		 FROM audit_logs
		 WHERE event_type = ANY($1)
		 ORDER BY created_at DESC
		 LIMIT $2`,
		eventTypes, limit,
	)
	if err != nil {
		return nil, fmt.Errorf("recent by types: %w", err)
	}
	defer rows.Close()

	var entries []*AuditEntry
	for rows.Next() {
		e := &AuditEntry{}
		var meta []byte
		if err := rows.Scan(&e.ID, &e.EventType, &e.ActorID, &e.TargetID, &e.IP, &e.Severity, &meta, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan recent event: %w", err)
		}
		e.Metadata = make(map[string]string)
		_ = json.Unmarshal(meta, &e.Metadata)
		entries = append(entries, e)
	}
	return entries, rows.Err()
}

// DistinctActors returns the number of distinct actor IDs for the given event types since the given time.
func (r *PostgresAuditRepository) DistinctActors(ctx context.Context, eventTypes []string, since time.Time) (int64, error) {
	if len(eventTypes) == 0 {
		return 0, nil
	}
	var count int64
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(DISTINCT actor_id) FROM audit_logs
		 WHERE event_type = ANY($1) AND created_at >= $2 AND actor_id != ''`,
		eventTypes, since,
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("distinct actors: %w", err)
	}
	return count, nil
}

// buildAuditWhere constructs WHERE clause and args from an AuditLogFilter.
func buildAuditWhere(filter AuditLogFilter) (string, []interface{}) {
	var conditions []string
	var args []interface{}
	idx := 1

	if filter.Action != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", idx))
		args = append(args, filter.Action)
		idx++
	}
	if filter.ActorID != "" {
		conditions = append(conditions, fmt.Sprintf("actor_id = $%d", idx))
		args = append(args, filter.ActorID)
		idx++
	}
	if filter.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", idx))
		args = append(args, *filter.StartDate)
		idx++
	}
	if filter.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", idx))
		args = append(args, *filter.EndDate)
		idx++
	}
	if filter.Severity != "" {
		conditions = append(conditions, fmt.Sprintf("severity = $%d", idx))
		args = append(args, filter.Severity)
	}

	if len(conditions) == 0 {
		return "", nil
	}
	return " WHERE " + strings.Join(conditions, " AND "), args
}
