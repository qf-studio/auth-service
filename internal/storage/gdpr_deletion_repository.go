package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// GDPRDeletionRepository defines the persistence operations for GDPR deletion requests.
type GDPRDeletionRepository interface {
	// Create stores a new deletion request. Returns ErrDeletionAlreadyRequested
	// if a pending request already exists for this user.
	Create(ctx context.Context, req *domain.DeletionRequest) (*domain.DeletionRequest, error)

	// FindByID retrieves a deletion request by primary key. Returns ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.DeletionRequest, error)

	// FindByUserID retrieves the most recent deletion request for a user.
	// Returns ErrNotFound if absent.
	FindByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error)

	// FindPendingByUserID retrieves the pending deletion request for a user.
	// Returns ErrNotFound if no pending request exists.
	FindPendingByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error)

	// FindDueForExecution returns all approved requests whose scheduled_at is in the past.
	FindDueForExecution(ctx context.Context, now time.Time) ([]domain.DeletionRequest, error)

	// UpdateStatus updates the status and relevant timestamps of a deletion request.
	UpdateStatus(ctx context.Context, id, status string, now time.Time) error

	// Cancel marks a deletion request as cancelled.
	Cancel(ctx context.Context, id, cancelledBy string, cancelledAt time.Time) error
}

// PostgresGDPRDeletionRepository implements GDPRDeletionRepository using pgx.
type PostgresGDPRDeletionRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresGDPRDeletionRepository creates a new PostgreSQL-backed GDPR deletion repository.
func NewPostgresGDPRDeletionRepository(pool *pgxpool.Pool) *PostgresGDPRDeletionRepository {
	return &PostgresGDPRDeletionRepository{pool: pool}
}

const deletionColumns = `id, user_id, status, reason, requested_at, scheduled_at, completed_at, cancelled_at, cancelled_by, created_at, updated_at`

func scanDeletion(row pgx.Row) (*domain.DeletionRequest, error) {
	rec := &domain.DeletionRequest{}
	err := row.Scan(
		&rec.ID, &rec.UserID, &rec.Status, &rec.Reason,
		&rec.RequestedAt, &rec.ScheduledAt, &rec.CompletedAt,
		&rec.CancelledAt, &rec.CancelledBy, &rec.CreatedAt, &rec.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return rec, nil
}

// Create inserts a new deletion request.
func (r *PostgresGDPRDeletionRepository) Create(ctx context.Context, req *domain.DeletionRequest) (*domain.DeletionRequest, error) {
	query := fmt.Sprintf(`
		INSERT INTO gdpr_deletion_requests (id, user_id, status, reason, requested_at, scheduled_at, completed_at, cancelled_at, cancelled_by, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING %s`, deletionColumns)

	out, err := scanDeletion(r.pool.QueryRow(ctx, query,
		req.ID, req.UserID, req.Status, req.Reason,
		req.RequestedAt, req.ScheduledAt, req.CompletedAt,
		req.CancelledAt, req.CancelledBy, req.CreatedAt, req.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("deletion for user %s: %w", req.UserID, ErrDeletionAlreadyRequested)
		}
		return nil, fmt.Errorf("insert deletion request: %w", err)
	}
	return out, nil
}

// FindByID retrieves a deletion request by ID.
func (r *PostgresGDPRDeletionRepository) FindByID(ctx context.Context, id string) (*domain.DeletionRequest, error) {
	query := fmt.Sprintf(`SELECT %s FROM gdpr_deletion_requests WHERE id = $1`, deletionColumns)

	rec, err := scanDeletion(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("deletion request %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("find deletion request by id: %w", err)
	}
	return rec, nil
}

// FindByUserID retrieves the most recent deletion request for a user.
func (r *PostgresGDPRDeletionRepository) FindByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error) {
	query := fmt.Sprintf(`SELECT %s FROM gdpr_deletion_requests WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1`, deletionColumns)

	rec, err := scanDeletion(r.pool.QueryRow(ctx, query, userID))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("deletion request for user %s: %w", userID, ErrNotFound)
		}
		return nil, fmt.Errorf("find deletion request by user: %w", err)
	}
	return rec, nil
}

// FindPendingByUserID retrieves the pending deletion request for a user.
func (r *PostgresGDPRDeletionRepository) FindPendingByUserID(ctx context.Context, userID string) (*domain.DeletionRequest, error) {
	query := fmt.Sprintf(`SELECT %s FROM gdpr_deletion_requests WHERE user_id = $1 AND status = $2`, deletionColumns)

	rec, err := scanDeletion(r.pool.QueryRow(ctx, query, userID, domain.DeletionStatusPending))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("pending deletion for user %s: %w", userID, ErrNotFound)
		}
		return nil, fmt.Errorf("find pending deletion by user: %w", err)
	}
	return rec, nil
}

// FindDueForExecution returns all approved requests whose scheduled_at is in the past.
func (r *PostgresGDPRDeletionRepository) FindDueForExecution(ctx context.Context, now time.Time) ([]domain.DeletionRequest, error) {
	query := fmt.Sprintf(`SELECT %s FROM gdpr_deletion_requests WHERE status = $1 AND scheduled_at <= $2 ORDER BY scheduled_at ASC`, deletionColumns)

	rows, err := r.pool.Query(ctx, query, domain.DeletionStatusApproved, now)
	if err != nil {
		return nil, fmt.Errorf("find due deletion requests: %w", err)
	}
	defer rows.Close()

	var requests []domain.DeletionRequest
	for rows.Next() {
		var req domain.DeletionRequest
		err := rows.Scan(
			&req.ID, &req.UserID, &req.Status, &req.Reason,
			&req.RequestedAt, &req.ScheduledAt, &req.CompletedAt,
			&req.CancelledAt, &req.CancelledBy, &req.CreatedAt, &req.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan deletion request: %w", err)
		}
		requests = append(requests, req)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deletion requests: %w", err)
	}

	return requests, nil
}

// UpdateStatus updates the status and timestamps of a deletion request.
func (r *PostgresGDPRDeletionRepository) UpdateStatus(ctx context.Context, id, status string, now time.Time) error {
	query := `UPDATE gdpr_deletion_requests SET status = $1, updated_at = $2, completed_at = CASE WHEN $1 = 'completed' THEN $2 ELSE completed_at END WHERE id = $3`

	tag, err := r.pool.Exec(ctx, query, status, now, id)
	if err != nil {
		return fmt.Errorf("update deletion status: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deletion request %s: %w", id, ErrNotFound)
	}
	return nil
}

// Cancel marks a deletion request as cancelled.
func (r *PostgresGDPRDeletionRepository) Cancel(ctx context.Context, id, cancelledBy string, cancelledAt time.Time) error {
	query := `UPDATE gdpr_deletion_requests SET status = $1, cancelled_at = $2, cancelled_by = $3, updated_at = $2 WHERE id = $4 AND status IN ('pending', 'approved')`

	tag, err := r.pool.Exec(ctx, query, domain.DeletionStatusCancelled, cancelledAt, cancelledBy, id)
	if err != nil {
		return fmt.Errorf("cancel deletion request: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deletion request %s: %w", id, ErrNotFound)
	}
	return nil
}
