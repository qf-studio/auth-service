package storage

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// ConsentGrantRepository defines persistence operations for remembered OIDC
// consent grants (see migrations/000018_consent_grants.up.sql).
type ConsentGrantRepository interface {
	// FindActive returns the non-revoked consent grant for the given
	// tenant+user+client, or ErrNotFound if none exists.
	FindActive(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error)
	// Create inserts a new active consent grant. Re-granting after a
	// revocation inserts a new row rather than reactivating the old one.
	Create(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error)
}

// PostgresConsentGrantRepository implements ConsentGrantRepository using PostgreSQL.
type PostgresConsentGrantRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresConsentGrantRepository creates a new PostgreSQL-backed consent grant repository.
func NewPostgresConsentGrantRepository(pool *pgxpool.Pool) *PostgresConsentGrantRepository {
	return &PostgresConsentGrantRepository{pool: pool}
}

const consentGrantColumns = `id, tenant_id, user_id, client_id, scopes, granted_at, revoked_at`

func scanConsentGrant(row pgx.Row) (*domain.ConsentGrant, error) {
	g := &domain.ConsentGrant{}
	err := row.Scan(&g.ID, &g.TenantID, &g.UserID, &g.ClientID, &g.Scopes, &g.GrantedAt, &g.RevokedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return g, nil
}

// FindActive retrieves the non-revoked consent grant for tenant+user+client.
func (r *PostgresConsentGrantRepository) FindActive(ctx context.Context, tenantID uuid.UUID, userID string, clientID uuid.UUID) (*domain.ConsentGrant, error) {
	query := fmt.Sprintf(`SELECT %s FROM consent_grants WHERE tenant_id = $1 AND user_id = $2 AND client_id = $3 AND revoked_at IS NULL`, consentGrantColumns)
	g, err := scanConsentGrant(r.pool.QueryRow(ctx, query, tenantID, userID, clientID))
	if err != nil {
		return nil, fmt.Errorf("find active consent grant for user %s client %s: %w", userID, clientID, err)
	}
	return g, nil
}

// Create inserts a new active consent grant.
func (r *PostgresConsentGrantRepository) Create(ctx context.Context, grant *domain.ConsentGrant) (*domain.ConsentGrant, error) {
	query := fmt.Sprintf(`
		INSERT INTO consent_grants (id, tenant_id, user_id, client_id, scopes, granted_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING %s`, consentGrantColumns)

	granted := grant.GrantedAt
	if granted.IsZero() {
		granted = time.Now().UTC()
	}

	g, err := scanConsentGrant(r.pool.QueryRow(ctx, query,
		grant.ID, grant.TenantID, grant.UserID, grant.ClientID, grant.Scopes, granted,
	))
	if err != nil {
		return nil, fmt.Errorf("insert consent grant: %w", err)
	}
	return g, nil
}
