package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DashboardRepository provides aggregate count queries for the admin dashboard.
type DashboardRepository interface {
	CountUsers(ctx context.Context) (int, error)
	CountLockedUsers(ctx context.Context) (int, error)
	CountClients(ctx context.Context) (int, error)
	CountActiveSessions(ctx context.Context) (int64, error)
	CountMFAEnabledUsers(ctx context.Context) (int64, error)
}

// PostgresDashboardRepository implements DashboardRepository with PostgreSQL.
type PostgresDashboardRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresDashboardRepository creates a new PostgresDashboardRepository.
func NewPostgresDashboardRepository(pool *pgxpool.Pool) *PostgresDashboardRepository {
	return &PostgresDashboardRepository{pool: pool}
}

// CountUsers returns the total number of non-deleted users.
func (r *PostgresDashboardRepository) CountUsers(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM users WHERE deleted_at IS NULL",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count users: %w", err)
	}
	return count, nil
}

// CountLockedUsers returns the number of currently locked users.
func (r *PostgresDashboardRepository) CountLockedUsers(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM users WHERE locked_at IS NOT NULL AND deleted_at IS NULL",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count locked users: %w", err)
	}
	return count, nil
}

// CountClients returns the total number of non-deleted clients.
func (r *PostgresDashboardRepository) CountClients(ctx context.Context) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM clients WHERE deleted_at IS NULL",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count clients: %w", err)
	}
	return count, nil
}

// CountActiveSessions returns the number of non-revoked, non-expired refresh tokens.
func (r *PostgresDashboardRepository) CountActiveSessions(ctx context.Context) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM refresh_tokens WHERE revoked_at IS NULL AND expires_at > $1",
		time.Now().UTC(),
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active sessions: %w", err)
	}
	return count, nil
}

// CountMFAEnabledUsers returns the number of users with confirmed MFA secrets.
func (r *PostgresDashboardRepository) CountMFAEnabledUsers(ctx context.Context) (int64, error) {
	var count int64
	err := r.pool.QueryRow(ctx,
		"SELECT COUNT(DISTINCT user_id) FROM mfa_secrets WHERE confirmed = true AND deleted_at IS NULL",
	).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count mfa users: %w", err)
	}
	return count, nil
}
