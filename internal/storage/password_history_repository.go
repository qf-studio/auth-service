package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// PasswordHistoryRepository defines persistence operations for password history entries.
type PasswordHistoryRepository interface {
	// Append adds a new password hash to the user's history.
	Append(ctx context.Context, entry *domain.PasswordHistoryEntry) error

	// FindByUserID retrieves the most recent password history entries for a user,
	// ordered by created_at descending, limited to the given count.
	FindByUserID(ctx context.Context, userID string, limit int) ([]domain.PasswordHistoryEntry, error)

	// Prune removes old entries beyond the retention count for a user,
	// keeping only the most recent `keep` entries. Returns the number of pruned rows.
	Prune(ctx context.Context, userID string, keep int) (int64, error)
}

// PostgresPasswordHistoryRepository implements PasswordHistoryRepository using PostgreSQL.
type PostgresPasswordHistoryRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresPasswordHistoryRepository creates a new PostgreSQL-backed password history repository.
func NewPostgresPasswordHistoryRepository(pool *pgxpool.Pool) *PostgresPasswordHistoryRepository {
	return &PostgresPasswordHistoryRepository{pool: pool}
}

// Append inserts a new password history entry.
func (r *PostgresPasswordHistoryRepository) Append(ctx context.Context, entry *domain.PasswordHistoryEntry) error {
	now := time.Now().UTC()
	query := `
		INSERT INTO password_history (id, user_id, password_hash, created_at)
		VALUES ($1, $2, $3, $4)`

	_, err := r.pool.Exec(ctx, query, entry.ID, entry.UserID, entry.PasswordHash, now)
	if err != nil {
		var pgErr interface{ SQLState() string }
		if errors.As(err, &pgErr) && pgErr.SQLState() == "23503" {
			return fmt.Errorf("user %s: %w", entry.UserID, ErrNotFound)
		}
		return fmt.Errorf("append password history: %w", err)
	}

	return nil
}

// FindByUserID returns the most recent password history entries for a user.
func (r *PostgresPasswordHistoryRepository) FindByUserID(ctx context.Context, userID string, limit int) ([]domain.PasswordHistoryEntry, error) {
	query := `
		SELECT id, user_id, password_hash, created_at
		FROM password_history
		WHERE user_id = $1
		ORDER BY created_at DESC
		LIMIT $2`

	rows, err := r.pool.Query(ctx, query, userID, limit)
	if err != nil {
		return nil, fmt.Errorf("find password history: %w", err)
	}
	defer rows.Close()

	var entries []domain.PasswordHistoryEntry
	for rows.Next() {
		var e domain.PasswordHistoryEntry
		if err := rows.Scan(&e.ID, &e.UserID, &e.PasswordHash, &e.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan password history: %w", err)
		}
		entries = append(entries, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate password history: %w", err)
	}

	return entries, nil
}

// Prune deletes old password history entries for a user, keeping only the most recent `keep` entries.
func (r *PostgresPasswordHistoryRepository) Prune(ctx context.Context, userID string, keep int) (int64, error) {
	query := `
		DELETE FROM password_history
		WHERE user_id = $1
		AND id NOT IN (
			SELECT id FROM password_history
			WHERE user_id = $1
			ORDER BY created_at DESC
			LIMIT $2
		)`

	tag, err := r.pool.Exec(ctx, query, userID, keep)
	if err != nil {
		return 0, fmt.Errorf("prune password history: %w", err)
	}

	return tag.RowsAffected(), nil
}
