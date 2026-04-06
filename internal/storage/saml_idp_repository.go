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

// SAMLIdPRepository defines persistence operations for SAML Identity Provider configurations.
type SAMLIdPRepository interface {
	Create(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error)
	FindByID(ctx context.Context, id uuid.UUID) (*domain.SAMLIdPConfig, error)
	FindByEntityID(ctx context.Context, entityID string) (*domain.SAMLIdPConfig, error)
	List(ctx context.Context) ([]*domain.SAMLIdPConfig, error)
	Update(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

// PostgresSAMLIdPRepository implements SAMLIdPRepository using PostgreSQL.
type PostgresSAMLIdPRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresSAMLIdPRepository creates a new PostgreSQL-backed SAML IdP repository.
func NewPostgresSAMLIdPRepository(pool *pgxpool.Pool) *PostgresSAMLIdPRepository {
	return &PostgresSAMLIdPRepository{pool: pool}
}

const samlIdPColumns = `id, entity_id, metadata_url, metadata_xml, sso_url, slo_url, certificate, name, attribute_mappings, enabled, created_at, updated_at`

func scanSAMLIdP(row pgx.Row) (*domain.SAMLIdPConfig, error) {
	idp := &domain.SAMLIdPConfig{}
	var id uuid.UUID
	var attrJSON []byte
	err := row.Scan(
		&id, &idp.EntityID, &idp.MetadataURL, &idp.MetadataXML,
		&idp.SSOURL, &idp.SLOURL, &idp.Certificate, &idp.Name,
		&attrJSON, &idp.Enabled,
		&idp.CreatedAt, &idp.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	idp.ID = id.String()
	if len(attrJSON) > 0 {
		if err := json.Unmarshal(attrJSON, &idp.AttributeMappings); err != nil {
			return nil, fmt.Errorf("unmarshal attribute mappings: %w", err)
		}
	}
	if idp.AttributeMappings == nil {
		idp.AttributeMappings = map[string]string{}
	}
	return idp, nil
}

// Create inserts a new SAML IdP configuration.
func (r *PostgresSAMLIdPRepository) Create(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error) {
	attrJSON, err := json.Marshal(idp.AttributeMappings)
	if err != nil {
		return nil, fmt.Errorf("marshal attribute mappings: %w", err)
	}

	query := fmt.Sprintf(`
		INSERT INTO saml_idp_configs (id, entity_id, metadata_url, metadata_xml, sso_url, slo_url, certificate, name, attribute_mappings, enabled, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING %s`, samlIdPColumns)

	result, err := scanSAMLIdP(r.pool.QueryRow(ctx, query,
		idp.ID, idp.EntityID, idp.MetadataURL, idp.MetadataXML,
		idp.SSOURL, idp.SLOURL, idp.Certificate, idp.Name,
		attrJSON, idp.Enabled,
		idp.CreatedAt, idp.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("saml idp %s: %w", idp.EntityID, ErrDuplicateSAMLIdP)
		}
		return nil, fmt.Errorf("insert saml idp: %w", err)
	}
	return result, nil
}

// FindByID retrieves a SAML IdP configuration by primary key.
func (r *PostgresSAMLIdPRepository) FindByID(ctx context.Context, id uuid.UUID) (*domain.SAMLIdPConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_idp_configs WHERE id = $1`, samlIdPColumns)
	idp, err := scanSAMLIdP(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find saml idp %s: %w", id, err)
	}
	return idp, nil
}

// FindByEntityID retrieves a SAML IdP configuration by its unique entity ID.
func (r *PostgresSAMLIdPRepository) FindByEntityID(ctx context.Context, entityID string) (*domain.SAMLIdPConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_idp_configs WHERE entity_id = $1`, samlIdPColumns)
	idp, err := scanSAMLIdP(r.pool.QueryRow(ctx, query, entityID))
	if err != nil {
		return nil, fmt.Errorf("find saml idp %q: %w", entityID, err)
	}
	return idp, nil
}

// List returns all SAML IdP configurations ordered by name.
func (r *PostgresSAMLIdPRepository) List(ctx context.Context) ([]*domain.SAMLIdPConfig, error) {
	query := fmt.Sprintf(`SELECT %s FROM saml_idp_configs ORDER BY name`, samlIdPColumns)
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list saml idps: %w", err)
	}
	defer rows.Close()

	var idps []*domain.SAMLIdPConfig
	for rows.Next() {
		var id uuid.UUID
		var attrJSON []byte
		idp := &domain.SAMLIdPConfig{}
		if err := rows.Scan(
			&id, &idp.EntityID, &idp.MetadataURL, &idp.MetadataXML,
			&idp.SSOURL, &idp.SLOURL, &idp.Certificate, &idp.Name,
			&attrJSON, &idp.Enabled,
			&idp.CreatedAt, &idp.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan saml idp: %w", err)
		}
		idp.ID = id.String()
		if len(attrJSON) > 0 {
			if err := json.Unmarshal(attrJSON, &idp.AttributeMappings); err != nil {
				return nil, fmt.Errorf("unmarshal attribute mappings: %w", err)
			}
		}
		if idp.AttributeMappings == nil {
			idp.AttributeMappings = map[string]string{}
		}
		idps = append(idps, idp)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate saml idps: %w", err)
	}
	return idps, nil
}

// Update modifies a SAML IdP configuration's mutable fields.
func (r *PostgresSAMLIdPRepository) Update(ctx context.Context, idp *domain.SAMLIdPConfig) (*domain.SAMLIdPConfig, error) {
	attrJSON, err := json.Marshal(idp.AttributeMappings)
	if err != nil {
		return nil, fmt.Errorf("marshal attribute mappings: %w", err)
	}

	query := fmt.Sprintf(`
		UPDATE saml_idp_configs
		SET metadata_url = $1, metadata_xml = $2, sso_url = $3, slo_url = $4,
		    certificate = $5, name = $6, attribute_mappings = $7, enabled = $8, updated_at = $9
		WHERE id = $10
		RETURNING %s`, samlIdPColumns)

	result, err := scanSAMLIdP(r.pool.QueryRow(ctx, query,
		idp.MetadataURL, idp.MetadataXML, idp.SSOURL, idp.SLOURL,
		idp.Certificate, idp.Name, attrJSON, idp.Enabled,
		time.Now().UTC(), idp.ID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("saml idp %s: %w", idp.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update saml idp: %w", err)
	}
	return result, nil
}

// Delete removes a SAML IdP configuration (cascades to linked accounts).
func (r *PostgresSAMLIdPRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM saml_idp_configs WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete saml idp %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("saml idp %s: %w", id, ErrNotFound)
	}
	return nil
}
