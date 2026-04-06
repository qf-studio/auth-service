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

// GDPRConsentRepository defines the persistence operations for GDPR consent records.
type GDPRConsentRepository interface {
	// Create stores a new consent record. Returns ErrDuplicateConsent if a record
	// of this consent type already exists for the user.
	Create(ctx context.Context, record *domain.ConsentRecord) (*domain.ConsentRecord, error)

	// FindByID retrieves a consent record by primary key. Returns ErrNotFound if absent.
	FindByID(ctx context.Context, id string) (*domain.ConsentRecord, error)

	// FindByUserID returns all consent records for a user.
	FindByUserID(ctx context.Context, userID string) ([]domain.ConsentRecord, error)

	// FindByUserIDAndType returns the consent record for a specific user and consent type.
	// Returns ErrNotFound if absent.
	FindByUserIDAndType(ctx context.Context, userID, consentType string) (*domain.ConsentRecord, error)

	// Revoke marks a consent record as revoked. Returns ErrNotFound if absent.
	Revoke(ctx context.Context, id string, revokedAt time.Time) error

	// DeleteByUserID removes all consent records for a user (used during account deletion).
	DeleteByUserID(ctx context.Context, userID string) error
}

// PostgresGDPRConsentRepository implements GDPRConsentRepository using pgx.
type PostgresGDPRConsentRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresGDPRConsentRepository creates a new PostgreSQL-backed GDPR consent repository.
func NewPostgresGDPRConsentRepository(pool *pgxpool.Pool) *PostgresGDPRConsentRepository {
	return &PostgresGDPRConsentRepository{pool: pool}
}

const consentColumns = `id, user_id, consent_type, granted, ip_address, user_agent, granted_at, revoked_at, created_at`

func scanConsent(row pgx.Row) (*domain.ConsentRecord, error) {
	rec := &domain.ConsentRecord{}
	err := row.Scan(
		&rec.ID, &rec.UserID, &rec.ConsentType, &rec.Granted,
		&rec.IPAddress, &rec.UserAgent, &rec.GrantedAt, &rec.RevokedAt, &rec.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return rec, nil
}

// Create inserts a new consent record.
func (r *PostgresGDPRConsentRepository) Create(ctx context.Context, record *domain.ConsentRecord) (*domain.ConsentRecord, error) {
	query := fmt.Sprintf(`
		INSERT INTO consent_records (id, user_id, consent_type, granted, ip_address, user_agent, granted_at, revoked_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING %s`, consentColumns)

	out, err := scanConsent(r.pool.QueryRow(ctx, query,
		record.ID, record.UserID, record.ConsentType, record.Granted,
		record.IPAddress, record.UserAgent, record.GrantedAt, record.RevokedAt, record.CreatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("consent %s for user %s: %w", record.ConsentType, record.UserID, ErrDuplicateConsent)
		}
		return nil, fmt.Errorf("insert consent record: %w", err)
	}
	return out, nil
}

// FindByID retrieves a consent record by ID.
func (r *PostgresGDPRConsentRepository) FindByID(ctx context.Context, id string) (*domain.ConsentRecord, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_records WHERE id = $1`, consentColumns)

	rec, err := scanConsent(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("consent %s: %w", id, ErrNotFound)
		}
		return nil, fmt.Errorf("find consent by id: %w", err)
	}
	return rec, nil
}

// FindByUserID returns all consent records for a user.
func (r *PostgresGDPRConsentRepository) FindByUserID(ctx context.Context, userID string) ([]domain.ConsentRecord, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_records WHERE user_id = $1 ORDER BY created_at DESC`, consentColumns)

	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("find consents by user: %w", err)
	}
	defer rows.Close()

	var records []domain.ConsentRecord
	for rows.Next() {
		var rec domain.ConsentRecord
		err := rows.Scan(
			&rec.ID, &rec.UserID, &rec.ConsentType, &rec.Granted,
			&rec.IPAddress, &rec.UserAgent, &rec.GrantedAt, &rec.RevokedAt, &rec.CreatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("scan consent record: %w", err)
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consent records: %w", err)
	}

	return records, nil
}

// FindByUserIDAndType returns the consent record for a specific user and type.
func (r *PostgresGDPRConsentRepository) FindByUserIDAndType(ctx context.Context, userID, consentType string) (*domain.ConsentRecord, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_records WHERE user_id = $1 AND consent_type = $2`, consentColumns)

	rec, err := scanConsent(r.pool.QueryRow(ctx, query, userID, consentType))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("consent %s for user %s: %w", consentType, userID, ErrNotFound)
		}
		return nil, fmt.Errorf("find consent by user and type: %w", err)
	}
	return rec, nil
}

// Revoke marks a consent record as revoked.
func (r *PostgresGDPRConsentRepository) Revoke(ctx context.Context, id string, revokedAt time.Time) error {
	query := `UPDATE consent_records SET granted = FALSE, revoked_at = $1 WHERE id = $2 AND granted = TRUE`

	tag, err := r.pool.Exec(ctx, query, revokedAt, id)
	if err != nil {
		return fmt.Errorf("revoke consent: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("consent %s: %w", id, ErrNotFound)
	}
	return nil
}

// DeleteByUserID removes all consent records for a user.
func (r *PostgresGDPRConsentRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM consent_records WHERE user_id = $1`

	_, err := r.pool.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("delete consent records for user %s: %w", userID, err)
	}
	return nil
}
