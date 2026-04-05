package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// ConsentSessionRepository defines persistence operations for OIDC consent sessions.
type ConsentSessionRepository interface {
	// Create stores a new consent session.
	Create(ctx context.Context, session *domain.ConsentSession) (*domain.ConsentSession, error)
	// FindByChallenge retrieves a consent session by its challenge token.
	FindByChallenge(ctx context.Context, challenge string) (*domain.ConsentSession, error)
	// FindByVerifier retrieves a consent session by its verifier token.
	FindByVerifier(ctx context.Context, verifier string) (*domain.ConsentSession, error)
	// UpdateState transitions the consent session to a new state, optionally setting granted scopes.
	UpdateState(ctx context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error
	// FindByUserAndClient retrieves active consent sessions for a user-client pair.
	FindByUserAndClient(ctx context.Context, userID string, clientID uuid.UUID) ([]*domain.ConsentSession, error)
	// Revoke marks all accepted consent sessions for a user-client pair as revoked.
	Revoke(ctx context.Context, userID string, clientID uuid.UUID) (int64, error)
	// DeleteExpired removes consent sessions that expired before the given cutoff.
	DeleteExpired(ctx context.Context, before time.Time) (int64, error)
}

// PostgresConsentSessionRepository implements ConsentSessionRepository using PostgreSQL.
type PostgresConsentSessionRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresConsentSessionRepository creates a new PostgreSQL-backed consent session repository.
func NewPostgresConsentSessionRepository(pool *pgxpool.Pool) *PostgresConsentSessionRepository {
	return &PostgresConsentSessionRepository{pool: pool}
}

const consentColumns = `id, challenge, verifier, client_id, user_id, requested_scopes, granted_scopes, state, login_session_id, encrypted_payload, created_at, updated_at, expires_at`

func scanConsent(row pgx.Row) (*domain.ConsentSession, error) {
	cs := &domain.ConsentSession{}
	err := row.Scan(
		&cs.ID, &cs.Challenge, &cs.Verifier, &cs.ClientID, &cs.UserID,
		&cs.RequestedScopes, &cs.GrantedScopes, &cs.State,
		&cs.LoginSessionID, &cs.EncryptedPayload,
		&cs.CreatedAt, &cs.UpdatedAt, &cs.ExpiresAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return cs, nil
}

// Create stores a new consent session.
func (r *PostgresConsentSessionRepository) Create(ctx context.Context, session *domain.ConsentSession) (*domain.ConsentSession, error) {
	query := fmt.Sprintf(`
		INSERT INTO consent_sessions (id, challenge, verifier, client_id, user_id, requested_scopes, granted_scopes, state, login_session_id, encrypted_payload, created_at, updated_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING %s`, consentColumns)

	cs, err := scanConsent(r.pool.QueryRow(ctx, query,
		session.ID, session.Challenge, session.Verifier, session.ClientID,
		session.UserID, session.RequestedScopes, session.GrantedScopes,
		session.State, session.LoginSessionID, session.EncryptedPayload,
		session.CreatedAt, session.UpdatedAt, session.ExpiresAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("consent session: %w", ErrDuplicateConsent)
		}
		return nil, fmt.Errorf("insert consent session: %w", err)
	}
	return cs, nil
}

// FindByChallenge retrieves a consent session by its challenge token.
func (r *PostgresConsentSessionRepository) FindByChallenge(ctx context.Context, challenge string) (*domain.ConsentSession, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_sessions WHERE challenge = $1`, consentColumns)
	cs, err := scanConsent(r.pool.QueryRow(ctx, query, challenge))
	if err != nil {
		return nil, fmt.Errorf("find consent by challenge: %w", err)
	}
	return cs, nil
}

// FindByVerifier retrieves a consent session by its verifier token.
func (r *PostgresConsentSessionRepository) FindByVerifier(ctx context.Context, verifier string) (*domain.ConsentSession, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_sessions WHERE verifier = $1`, consentColumns)
	cs, err := scanConsent(r.pool.QueryRow(ctx, query, verifier))
	if err != nil {
		return nil, fmt.Errorf("find consent by verifier: %w", err)
	}
	return cs, nil
}

// UpdateState transitions the consent session to a new state, optionally setting granted scopes.
func (r *PostgresConsentSessionRepository) UpdateState(ctx context.Context, id uuid.UUID, state domain.ConsentState, grantedScopes []string) error {
	now := time.Now().UTC()
	query := `UPDATE consent_sessions SET state = $1, granted_scopes = $2, updated_at = $3 WHERE id = $4`
	tag, err := r.pool.Exec(ctx, query, state, grantedScopes, now, id)
	if err != nil {
		return fmt.Errorf("update consent state: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("consent session %s: %w", id, ErrNotFound)
	}
	return nil
}

// FindByUserAndClient retrieves active consent sessions for a user-client pair.
func (r *PostgresConsentSessionRepository) FindByUserAndClient(ctx context.Context, userID string, clientID uuid.UUID) ([]*domain.ConsentSession, error) {
	query := fmt.Sprintf(
		`SELECT %s FROM consent_sessions WHERE user_id = $1 AND client_id = $2 AND state = 'accepted' ORDER BY created_at DESC`,
		consentColumns,
	)
	rows, err := r.pool.Query(ctx, query, userID, clientID)
	if err != nil {
		return nil, fmt.Errorf("find consent sessions: %w", err)
	}
	defer rows.Close()

	var sessions []*domain.ConsentSession
	for rows.Next() {
		cs := &domain.ConsentSession{}
		if err := rows.Scan(
			&cs.ID, &cs.Challenge, &cs.Verifier, &cs.ClientID, &cs.UserID,
			&cs.RequestedScopes, &cs.GrantedScopes, &cs.State,
			&cs.LoginSessionID, &cs.EncryptedPayload,
			&cs.CreatedAt, &cs.UpdatedAt, &cs.ExpiresAt,
		); err != nil {
			return nil, fmt.Errorf("scan consent session: %w", err)
		}
		sessions = append(sessions, cs)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate consent sessions: %w", err)
	}
	return sessions, nil
}

// Revoke marks all accepted consent sessions for a user-client pair as revoked.
func (r *PostgresConsentSessionRepository) Revoke(ctx context.Context, userID string, clientID uuid.UUID) (int64, error) {
	now := time.Now().UTC()
	tag, err := r.pool.Exec(ctx,
		`UPDATE consent_sessions SET state = 'revoked', updated_at = $1 WHERE user_id = $2 AND client_id = $3 AND state = 'accepted'`,
		now, userID, clientID,
	)
	if err != nil {
		return 0, fmt.Errorf("revoke consent sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}

// DeleteExpired removes consent sessions that expired before the given cutoff.
func (r *PostgresConsentSessionRepository) DeleteExpired(ctx context.Context, before time.Time) (int64, error) {
	tag, err := r.pool.Exec(ctx,
		`DELETE FROM consent_sessions WHERE expires_at IS NOT NULL AND expires_at < $1`, before,
	)
	if err != nil {
		return 0, fmt.Errorf("delete expired consent sessions: %w", err)
	}
	return tag.RowsAffected(), nil
}
