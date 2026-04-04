package storage

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/api"
)

// AuditRepository defines persistence operations for querying audit events.
type AuditRepository interface {
	// List returns a paginated list of audit events matching the given filters.
	List(ctx context.Context, limit, offset int, filter api.AuditFilter) ([]api.AdminAuditEvent, int, error)
}

// PostgresAuditRepository implements AuditRepository using PostgreSQL.
type PostgresAuditRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditRepository creates a new PostgreSQL-backed audit repository.
func NewPostgresAuditRepository(pool *pgxpool.Pool) *PostgresAuditRepository {
	return &PostgresAuditRepository{pool: pool}
}

// List queries the audit_events table with optional filters and pagination.
func (r *PostgresAuditRepository) List(ctx context.Context, limit, offset int, filter api.AuditFilter) ([]api.AdminAuditEvent, int, error) {
	var conditions []string
	var args []interface{}
	argIdx := 1

	if filter.UserID != "" {
		conditions = append(conditions, fmt.Sprintf("user_id = $%d", argIdx))
		args = append(args, filter.UserID)
		argIdx++
	}
	if filter.ClientID != "" {
		conditions = append(conditions, fmt.Sprintf("client_id = $%d", argIdx))
		args = append(args, filter.ClientID)
		argIdx++
	}
	if filter.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", argIdx))
		args = append(args, filter.EventType)
		argIdx++
	}
	if filter.StartDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at >= $%d", argIdx))
		args = append(args, filter.StartDate)
		argIdx++
	}
	if filter.EndDate != nil {
		conditions = append(conditions, fmt.Sprintf("created_at <= $%d", argIdx))
		args = append(args, filter.EndDate)
		argIdx++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM audit_events %s", where)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit events: %w", err)
	}

	// Fetch the page.
	dataQuery := fmt.Sprintf(
		"SELECT id, user_id, client_id, event_type, ip_address, user_agent, metadata, created_at FROM audit_events %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d",
		where, argIdx, argIdx+1,
	)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, dataQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("query audit events: %w", err)
	}
	defer rows.Close()

	events := make([]api.AdminAuditEvent, 0)
	for rows.Next() {
		var e api.AdminAuditEvent
		var userID, clientID, ipAddress, userAgent *string
		var metadata map[string]string
		var createdAt time.Time

		if err := rows.Scan(&e.ID, &userID, &clientID, &e.EventType, &ipAddress, &userAgent, &metadata, &createdAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit event: %w", err)
		}

		if userID != nil {
			e.UserID = *userID
		}
		if clientID != nil {
			e.ClientID = *clientID
		}
		if ipAddress != nil {
			e.IPAddress = *ipAddress
		}
		if userAgent != nil {
			e.UserAgent = *userAgent
		}
		e.Metadata = metadata
		e.CreatedAt = createdAt
		events = append(events, e)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit events: %w", err)
	}

	return events, total, nil
}
