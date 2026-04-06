package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// PasswordPolicyRepository defines persistence operations for password policies.
type PasswordPolicyRepository interface {
	// Upsert creates or updates a password policy by ID. Returns the saved record.
	Upsert(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error)

	// FindByID retrieves a password policy by ID. Returns ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.PasswordPolicy, error)

	// Delete removes a password policy by ID. Returns ErrNotFound if absent.
	Delete(ctx context.Context, id string) error
}

// PostgresPasswordPolicyRepository implements PasswordPolicyRepository using PostgreSQL.
type PostgresPasswordPolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresPasswordPolicyRepository creates a new PostgreSQL-backed password policy repository.
func NewPostgresPasswordPolicyRepository(pool *pgxpool.Pool) *PostgresPasswordPolicyRepository {
	return &PostgresPasswordPolicyRepository{pool: pool}
}

// Upsert creates or updates a password policy. Uses INSERT ... ON CONFLICT to handle both cases.
func (r *PostgresPasswordPolicyRepository) Upsert(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
	now := time.Now().UTC()
	query := `
		INSERT INTO password_policies (id, min_length, max_length, max_age_days, history_count, require_mfa, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
		ON CONFLICT (id) DO UPDATE SET
			min_length    = EXCLUDED.min_length,
			max_length    = EXCLUDED.max_length,
			max_age_days  = EXCLUDED.max_age_days,
			history_count = EXCLUDED.history_count,
			require_mfa   = EXCLUDED.require_mfa,
			updated_at    = EXCLUDED.updated_at
		RETURNING id, min_length, max_length, max_age_days, history_count, require_mfa, created_at, updated_at`

	out := &domain.PasswordPolicy{}
	err := r.pool.QueryRow(ctx, query,
		policy.ID, policy.MinLength, policy.MaxLength, policy.MaxAgeDays,
		policy.HistoryCount, policy.RequireMFA, now,
	).Scan(
		&out.ID, &out.MinLength, &out.MaxLength, &out.MaxAgeDays,
		&out.HistoryCount, &out.RequireMFA, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("upsert password policy: %w", err)
	}

	return out, nil
}

// FindByID retrieves a password policy by its ID.
func (r *PostgresPasswordPolicyRepository) FindByID(ctx context.Context, id string) (*domain.PasswordPolicy, error) {
	query := `
		SELECT id, min_length, max_length, max_age_days, history_count, require_mfa, created_at, updated_at
		FROM password_policies
		WHERE id = $1`

	out := &domain.PasswordPolicy{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&out.ID, &out.MinLength, &out.MaxLength, &out.MaxAgeDays,
		&out.HistoryCount, &out.RequireMFA, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("policy %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("find password policy: %w", err)
	}

	return out, nil
}

// Delete removes a password policy by ID.
func (r *PostgresPasswordPolicyRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM password_policies WHERE id = $1`

	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete password policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy %s: %w", id, ErrNotFound)
	}

	return nil
}
