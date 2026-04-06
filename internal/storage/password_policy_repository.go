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

// PasswordPolicyRepository defines persistence operations for password policies.
type PasswordPolicyRepository interface {
	List(ctx context.Context, limit, offset int) ([]*domain.PasswordPolicy, int, error)
	FindByID(ctx context.Context, id string) (*domain.PasswordPolicy, error)
	Create(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error)
	Update(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error)
	SoftDelete(ctx context.Context, id string) error
	// ComplianceReport returns users with expired passwords, users flagged for
	// forced password change, and a count of policy violations.
	ComplianceReport(ctx context.Context) (*ComplianceData, error)
}

// ComplianceData holds the raw data for the compliance report.
type ComplianceData struct {
	ExpiredPasswordCount    int
	ForceChangeCount        int
	PolicyViolationCount    int
	ExpiredPasswordUserIDs  []string
	ForceChangeUserIDs      []string
}

// ErrDuplicatePolicyName indicates a policy with the given name already exists.
var ErrDuplicatePolicyName = errors.New("duplicate policy name")

// PostgresPasswordPolicyRepository implements PasswordPolicyRepository using PostgreSQL.
type PostgresPasswordPolicyRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresPasswordPolicyRepository creates a new PostgreSQL-backed password policy repository.
func NewPostgresPasswordPolicyRepository(pool *pgxpool.Pool) *PostgresPasswordPolicyRepository {
	return &PostgresPasswordPolicyRepository{pool: pool}
}

const policyColumns = `id, name, min_length, max_length, max_age_days, history_count, require_mfa, is_default, created_at, updated_at, deleted_at`

func scanPolicy(row pgx.Row) (*domain.PasswordPolicy, error) {
	p := &domain.PasswordPolicy{}
	err := row.Scan(
		&p.ID, &p.Name, &p.MinLength, &p.MaxLength, &p.MaxAgeDays,
		&p.HistoryCount, &p.RequireMFA, &p.IsDefault,
		&p.CreatedAt, &p.UpdatedAt, &p.DeletedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return p, nil
}

// List returns a paginated list of non-deleted password policies.
func (r *PostgresPasswordPolicyRepository) List(ctx context.Context, limit, offset int) ([]*domain.PasswordPolicy, int, error) {
	var total int
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM password_policies WHERE deleted_at IS NULL`).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count password policies: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM password_policies WHERE deleted_at IS NULL ORDER BY created_at DESC LIMIT $1 OFFSET $2`, policyColumns)
	rows, err := r.pool.Query(ctx, query, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list password policies: %w", err)
	}
	defer rows.Close()

	var policies []*domain.PasswordPolicy
	for rows.Next() {
		p := &domain.PasswordPolicy{}
		if err := rows.Scan(
			&p.ID, &p.Name, &p.MinLength, &p.MaxLength, &p.MaxAgeDays,
			&p.HistoryCount, &p.RequireMFA, &p.IsDefault,
			&p.CreatedAt, &p.UpdatedAt, &p.DeletedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan password policy: %w", err)
		}
		policies = append(policies, p)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate password policies: %w", err)
	}

	return policies, total, nil
}

// FindByID retrieves a password policy by ID.
func (r *PostgresPasswordPolicyRepository) FindByID(ctx context.Context, id string) (*domain.PasswordPolicy, error) {
	query := fmt.Sprintf(`SELECT %s FROM password_policies WHERE id = $1 AND deleted_at IS NULL`, policyColumns)
	p, err := scanPolicy(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find password policy %s: %w", id, err)
	}
	return p, nil
}

// Create inserts a new password policy.
func (r *PostgresPasswordPolicyRepository) Create(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
	query := fmt.Sprintf(`
		INSERT INTO password_policies (id, name, min_length, max_length, max_age_days, history_count, require_mfa, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, policyColumns)

	p, err := scanPolicy(r.pool.QueryRow(ctx, query,
		policy.ID, policy.Name, policy.MinLength, policy.MaxLength,
		policy.MaxAgeDays, policy.HistoryCount, policy.RequireMFA, policy.IsDefault,
		policy.CreatedAt, policy.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("policy name %s: %w", policy.Name, ErrDuplicatePolicyName)
		}
		return nil, fmt.Errorf("insert password policy: %w", err)
	}
	return p, nil
}

// Update modifies mutable fields of a password policy.
func (r *PostgresPasswordPolicyRepository) Update(ctx context.Context, policy *domain.PasswordPolicy) (*domain.PasswordPolicy, error) {
	query := fmt.Sprintf(`
		UPDATE password_policies
		SET name = $1, min_length = $2, max_length = $3, max_age_days = $4,
		    history_count = $5, require_mfa = $6, is_default = $7, updated_at = $8
		WHERE id = $9 AND deleted_at IS NULL
		RETURNING %s`, policyColumns)

	p, err := scanPolicy(r.pool.QueryRow(ctx, query,
		policy.Name, policy.MinLength, policy.MaxLength, policy.MaxAgeDays,
		policy.HistoryCount, policy.RequireMFA, policy.IsDefault, time.Now().UTC(),
		policy.ID,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("policy name %s: %w", policy.Name, ErrDuplicatePolicyName)
		}
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("password policy %s: %w", policy.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update password policy: %w", err)
	}
	return p, nil
}

// SoftDelete sets deleted_at on the password policy record.
func (r *PostgresPasswordPolicyRepository) SoftDelete(ctx context.Context, id string) error {
	now := time.Now().UTC()
	query := `UPDATE password_policies SET deleted_at = $1, updated_at = $1 WHERE id = $2 AND deleted_at IS NULL`

	tag, err := r.pool.Exec(ctx, query, now, id)
	if err != nil {
		return fmt.Errorf("soft delete password policy %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		var exists bool
		_ = r.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM password_policies WHERE id = $1)`, id).Scan(&exists)
		if exists {
			return fmt.Errorf("password policy %s already deleted: %w", id, ErrAlreadyDeleted)
		}
		return fmt.Errorf("password policy %s: %w", id, ErrNotFound)
	}
	return nil
}

// ComplianceReport queries users table for password compliance data.
// It checks: users with expired passwords (based on default policy max_age_days),
// users flagged for forced password change, and total violation count.
func (r *PostgresPasswordPolicyRepository) ComplianceReport(ctx context.Context) (*ComplianceData, error) {
	data := &ComplianceData{}

	// Get default policy max_age_days (0 means no expiry).
	var maxAgeDays int
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE((SELECT max_age_days FROM password_policies WHERE is_default = true AND deleted_at IS NULL LIMIT 1), 0)`,
	).Scan(&maxAgeDays)
	if err != nil {
		return nil, fmt.Errorf("get default policy: %w", err)
	}

	// Users with expired passwords (only if max_age_days > 0).
	if maxAgeDays > 0 {
		expiredRows, err := r.pool.Query(ctx,
			`SELECT id FROM users
			 WHERE deleted_at IS NULL
			   AND password_changed_at IS NOT NULL
			   AND password_changed_at < now() - ($1 || ' days')::interval`,
			fmt.Sprintf("%d", maxAgeDays),
		)
		if err != nil {
			return nil, fmt.Errorf("query expired passwords: %w", err)
		}
		defer expiredRows.Close()

		for expiredRows.Next() {
			var uid string
			if err := expiredRows.Scan(&uid); err != nil {
				return nil, fmt.Errorf("scan expired user: %w", err)
			}
			data.ExpiredPasswordUserIDs = append(data.ExpiredPasswordUserIDs, uid)
		}
		if err := expiredRows.Err(); err != nil {
			return nil, fmt.Errorf("iterate expired users: %w", err)
		}
		data.ExpiredPasswordCount = len(data.ExpiredPasswordUserIDs)
	}

	// Users flagged for forced password change.
	forceRows, err := r.pool.Query(ctx,
		`SELECT id FROM users WHERE deleted_at IS NULL AND force_password_change = true`,
	)
	if err != nil {
		return nil, fmt.Errorf("query force change users: %w", err)
	}
	defer forceRows.Close()

	for forceRows.Next() {
		var uid string
		if err := forceRows.Scan(&uid); err != nil {
			return nil, fmt.Errorf("scan force change user: %w", err)
		}
		data.ForceChangeUserIDs = append(data.ForceChangeUserIDs, uid)
	}
	if err := forceRows.Err(); err != nil {
		return nil, fmt.Errorf("iterate force change users: %w", err)
	}
	data.ForceChangeCount = len(data.ForceChangeUserIDs)

	// Total violations = expired + forced.
	data.PolicyViolationCount = data.ExpiredPasswordCount + data.ForceChangeCount

	return data, nil
}
