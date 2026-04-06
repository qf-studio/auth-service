package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// SAMLAccountRepository defines persistence operations for SAML account links.
type SAMLAccountRepository interface {
	Create(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.SAMLAccount, error)
	FindByIdPAndNameID(ctx context.Context, idpID uuid.UUID, nameID string) (*domain.SAMLAccount, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.SAMLAccount, error)
	ListByIdPID(ctx context.Context, idpID uuid.UUID) ([]*domain.SAMLAccount, error)
	Update(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// PostgresSAMLAccountRepository implements SAMLAccountRepository using PostgreSQL.
type PostgresSAMLAccountRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresSAMLAccountRepository creates a new PostgreSQL-backed SAML account repository.
func NewPostgresSAMLAccountRepository(pool *pgxpool.Pool) *PostgresSAMLAccountRepository {
	return &PostgresSAMLAccountRepository{pool: pool}
}

const samlAccountColumns = `id, user_id, idp_id, name_id, session_index, cached_attributes, created_at, updated_at`

func scanSAMLAccount(row pgx.Row) (*domain.SAMLAccount, error) {
	acct := &domain.SAMLAccount{}
	var id, userID, idpID uuid.UUID
	var attrJSON []byte
	err := row.Scan(
		&id, &userID, &idpID, &acct.NameID,
		&acct.SessionIndex, &attrJSON,
		&acct.CreatedAt, &acct.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	acct.ID = id.String()
	acct.UserID = userID.String()
	acct.IdPID = idpID.String()
	if len(attrJSON) > 0 {
		if err := json.Unmarshal(attrJSON, &acct.CachedAttributes); err != nil {
			return nil, fmt.Errorf("unmarshal cached attributes: %w", err)
		}
	}
	if acct.CachedAttributes == nil {
		acct.CachedAttributes = map[string]string{}
	}
	return acct, nil
}

// Create inserts a new SAML account link.
func (r *PostgresSAMLAccountRepository) Create(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error) {
	attrJSON, err := json.Marshal(acct.CachedAttributes)
	if err != nil {
		return nil, fmt.Errorf("marshal cached attributes: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO saml_accounts (id, user_id, idp_id, name_id, session_index, cached_attributes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, samlAccountColumns)

	result, err := scanSAMLAccount(r.pool.QueryRow(ctx, query,
		acct.ID, acct.UserID, acct.IdPID, acct.NameID,
		acct.SessionIndex, attrJSON,
		acct.CreatedAt, acct.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("saml account %s/%s: %w", acct.IdPID, acct.NameID, ErrDuplicateSAMLAccount)
		}
		return nil, fmt.Errorf("insert saml account: %w", err)
	}
	return result, nil
}

// FindByID retrieves a SAML account by primary key.
func (r *PostgresSAMLAccountRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.SAMLAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_accounts WHERE id = $1`, samlAccountColumns)
	acct, err := scanSAMLAccount(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find saml account %s: %w", id, err)
	}
	return acct, nil
}

// FindByIdPAndNameID retrieves a SAML account by its unique IdP + NameID combination.
func (r *PostgresSAMLAccountRepository) FindByIdPAndNameID(ctx context.Context, idpID uuid.UUID, nameID string) (*domain.SAMLAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_accounts WHERE idp_id = $1 AND name_id = $2`, samlAccountColumns)
	acct, err := scanSAMLAccount(r.pool.QueryRow(ctx, query, idpID, nameID))
	if err != nil {
		return nil, fmt.Errorf("find saml account idp=%s name_id=%q: %w", idpID, nameID, err)
	}
	return acct, nil
}

// ListByUserID returns all SAML accounts linked to a given user.
func (r *PostgresSAMLAccountRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*domain.SAMLAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_accounts WHERE user_id = $1 ORDER BY created_at`, samlAccountColumns)
	rows, err := r.pool.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("list saml accounts by user: %w", err)
	}
	defer rows.Close()

	var accts []*domain.SAMLAccount
	for rows.Next() {
		var id, uid, idpID uuid.UUID
		var attrJSON []byte
		acct := &domain.SAMLAccount{}
		if err := rows.Scan(
			&id, &uid, &idpID, &acct.NameID,
			&acct.SessionIndex, &attrJSON,
			&acct.CreatedAt, &acct.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan saml account: %w", err)
		}
		acct.ID = id.String()
		acct.UserID = uid.String()
		acct.IdPID = idpID.String()
		if len(attrJSON) > 0 {
			if err := json.Unmarshal(attrJSON, &acct.CachedAttributes); err != nil {
				return nil, fmt.Errorf("unmarshal cached attributes: %w", err)
			}
		}
		if acct.CachedAttributes == nil {
			acct.CachedAttributes = map[string]string{}
		}
		accts = append(accts, acct)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saml accounts: %w", err)
	}
	return accts, nil
}

// ListByIdPID returns all SAML accounts linked to a given IdP.
func (r *PostgresSAMLAccountRepository) ListByIdPID(ctx context.Context, idpID uuid.UUID) ([]*domain.SAMLAccount, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_accounts WHERE idp_id = $1 ORDER BY created_at`, samlAccountColumns)
	rows, err := r.pool.Query(ctx, query, idpID)
	if err != nil {
		return nil, fmt.Errorf("list saml accounts by idp: %w", err)
	}
	defer rows.Close()

	var accts []*domain.SAMLAccount
	for rows.Next() {
		var id, uid, idpIDVal uuid.UUID
		var attrJSON []byte
		acct := &domain.SAMLAccount{}
		if err := rows.Scan(
			&id, &uid, &idpIDVal, &acct.NameID,
			&acct.SessionIndex, &attrJSON,
			&acct.CreatedAt, &acct.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan saml account: %w", err)
		}
		acct.ID = id.String()
		acct.UserID = uid.String()
		acct.IdPID = idpIDVal.String()
		if len(attrJSON) > 0 {
			if err := json.Unmarshal(attrJSON, &acct.CachedAttributes); err != nil {
				return nil, fmt.Errorf("unmarshal cached attributes: %w", err)
			}
		}
		if acct.CachedAttributes == nil {
			acct.CachedAttributes = map[string]string{}
		}
		accts = append(accts, acct)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saml accounts: %w", err)
	}
	return accts, nil
}

// Update modifies a SAML account's mutable fields.
func (r *PostgresSAMLAccountRepository) Update(ctx context.Context, acct *domain.SAMLAccount) (*domain.SAMLAccount, error) {
	attrJSON, err := json.Marshal(acct.CachedAttributes)
	if err != nil {
		return nil, fmt.Errorf("marshal cached attributes: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE saml_accounts
		SET session_index = $1, cached_attributes = $2, updated_at = $3
		WHERE id = $4
		RETURNING %s`, samlAccountColumns)

	result, err := scanSAMLAccount(r.pool.QueryRow(ctx, query,
		acct.SessionIndex, attrJSON, time.Now().UTC(), acct.ID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("saml account %s: %w", acct.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update saml account: %w", err)
	}
	return result, nil
}

// Delete removes a SAML account link.
func (r *PostgresSAMLAccountRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM saml_accounts WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete saml account %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("saml account %s: %w", id, ErrNotFound)
	}
	return nil
}
