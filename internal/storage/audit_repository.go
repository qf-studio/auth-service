package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AuditRepository defines persistence operations for audit log entries.
type AuditRepository interface {
	// Create inserts a single audit log entry.
	Create(ctx context.Context, entry *domain.AuditLog) error

	// List returns audit logs ordered by created_at DESC with pagination.
	// Optional filters: actorID, targetID, eventType (empty string = no filter).
	List(ctx context.Context, limit, offset int, actorID, targetID, eventType string) ([]*domain.AuditLog, int, error)

	// FindByID returns a single audit log entry.
	FindByID(ctx context.Context, id uuid.UUID) (*domain.AuditLog, error)
}

const auditLogColumns = `id, event_type, actor_id, target_id, ip, metadata, created_at`

func scanAuditLog(row pgx.Row) (*domain.AuditLog, error) {
	a := &domain.AuditLog{}
	var metaJSON []byte
	err := row.Scan(&a.ID, &a.EventType, &a.ActorID, &a.TargetID, &a.IP, &metaJSON, &a.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	if len(metaJSON) > 0 {
		if jsonErr := json.Unmarshal(metaJSON, &a.Metadata); jsonErr != nil {
			return nil, fmt.Errorf("unmarshal audit metadata: %w", jsonErr)
		}
	}
	return a, nil
}

// PostgresAuditRepository implements AuditRepository using PostgreSQL.
type PostgresAuditRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresAuditRepository creates a new PostgreSQL-backed audit repository.
func NewPostgresAuditRepository(pool *pgxpool.Pool) *PostgresAuditRepository {
	return &PostgresAuditRepository{pool: pool}
}

// Create inserts a single audit log entry.
func (r *PostgresAuditRepository) Create(ctx context.Context, entry *domain.AuditLog) error {
	metaJSON, err := json.Marshal(entry.Metadata)
	if err != nil {
		return fmt.Errorf("marshal audit metadata: %w", err)
	}

	_, err = r.pool.Exec(ctx,
		`INSERT INTO audit_logs (event_type, actor_id, target_id, ip, metadata, created_at)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		entry.EventType, entry.ActorID, entry.TargetID, entry.IP, metaJSON, entry.CreatedAt,
	)
	if err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return nil
}

// List returns paginated audit logs with optional filters.
func (r *PostgresAuditRepository) List(ctx context.Context, limit, offset int, actorID, targetID, eventType string) ([]*domain.AuditLog, int, error) {
	var (
		conditions []string
		args       []any
		argIdx     int
	)

	addFilter := func(column, value string) {
		if value != "" {
			argIdx++
			conditions = append(conditions, fmt.Sprintf("%s = $%d", column, argIdx))
			args = append(args, value)
		}
	}

	addFilter("actor_id", actorID)
	addFilter("target_id", targetID)
	addFilter("event_type", eventType)

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	// Count total matching rows.
	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM audit_logs %s`, where)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count audit logs: %w", err)
	}

	// Fetch page.
	argIdx++
	limitArg := argIdx
	argIdx++
	offsetArg := argIdx
	selectQuery := fmt.Sprintf(
		`SELECT %s FROM audit_logs %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		auditLogColumns, where, limitArg, offsetArg,
	)
	args = append(args, limit, offset)

	rows, err := r.pool.Query(ctx, selectQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var results []*domain.AuditLog
	for rows.Next() {
		a := &domain.AuditLog{}
		var metaJSON []byte
		if err := rows.Scan(&a.ID, &a.EventType, &a.ActorID, &a.TargetID, &a.IP, &metaJSON, &a.CreatedAt); err != nil {
			return nil, 0, fmt.Errorf("scan audit log row: %w", err)
		}
		if len(metaJSON) > 0 {
			if jsonErr := json.Unmarshal(metaJSON, &a.Metadata); jsonErr != nil {
				return nil, 0, fmt.Errorf("unmarshal audit metadata: %w", jsonErr)
			}
		}
		results = append(results, a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate audit log rows: %w", err)
	}

	return results, total, nil
}

// FindByID returns a single audit log entry by ID.
func (r *PostgresAuditRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.AuditLog, error) {
	query := fmt.Sprintf(`SELECT %s FROM audit_logs WHERE id = $1`, auditLogColumns)
	return scanAuditLog(r.pool.QueryRow(ctx, query, id))
}
