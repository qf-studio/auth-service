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

// RARRepository defines persistence operations for the RFC 9396 resource type registry.
type RARRepository interface {
	// Resource type CRUD.
	CreateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error)
	FindResourceTypeByID(ctx context.Context, id uuid.UUID) (*domain.RARResourceType, error)
	FindResourceTypeByType(ctx context.Context, typeName string) (*domain.RARResourceType, error)
	ListResourceTypes(ctx context.Context) ([]*domain.RARResourceType, error)
	UpdateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error)
	DeleteResourceType(ctx context.Context, id uuid.UUID) error

	// Client-to-type associations.
	AllowClientType(ctx context.Context, clientID, resourceTypeID uuid.UUID) error
	RevokeClientType(ctx context.Context, clientID, resourceTypeID uuid.UUID) error
	ListClientAllowedTypes(ctx context.Context, clientID uuid.UUID) ([]*domain.RARResourceType, error)
	IsClientTypeAllowed(ctx context.Context, clientID uuid.UUID, typeName string) (bool, error)
}

// PostgresRARRepository implements RARRepository using PostgreSQL.
type PostgresRARRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresRARRepository creates a new PostgreSQL-backed RAR repository.
func NewPostgresRARRepository(pool *pgxpool.Pool) *PostgresRARRepository {
	return &PostgresRARRepository{pool: pool}
}

const rarResourceTypeColumns = `id, type, description, allowed_actions, allowed_datatypes, created_at, updated_at`

func scanRARResourceType(row pgx.Row) (*domain.RARResourceType, error) {
	rt := &domain.RARResourceType{}
	err := row.Scan(
		&rt.ID, &rt.Type, &rt.Description,
		&rt.AllowedActions, &rt.AllowedDataTypes,
		&rt.CreatedAt, &rt.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return rt, nil
}

// CreateResourceType inserts a new RAR resource type.
func (r *PostgresRARRepository) CreateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error) {
	query := fmt.Sprintf(`
		INSERT INTO rar_resource_types (id, type, description, allowed_actions, allowed_datatypes, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING %s`, rarResourceTypeColumns)

	result, err := scanRARResourceType(r.pool.QueryRow(ctx, query,
		rt.ID, rt.Type, rt.Description,
		rt.AllowedActions, rt.AllowedDataTypes,
		rt.CreatedAt, rt.UpdatedAt,
	))
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, fmt.Errorf("rar type %s: %w", rt.Type, ErrDuplicateRARType)
		}
		return nil, fmt.Errorf("insert rar resource type: %w", err)
	}
	return result, nil
}

// FindResourceTypeByID retrieves a resource type by primary key.
func (r *PostgresRARRepository) FindResourceTypeByID(ctx context.Context, id uuid.UUID) (*domain.RARResourceType, error) {
	query := fmt.Sprintf(`SELECT %s FROM rar_resource_types WHERE id = $1`, rarResourceTypeColumns)
	rt, err := scanRARResourceType(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("find rar resource type %s: %w", id, err)
	}
	return rt, nil
}

// FindResourceTypeByType retrieves a resource type by its unique type identifier.
func (r *PostgresRARRepository) FindResourceTypeByType(ctx context.Context, typeName string) (*domain.RARResourceType, error) {
	query := fmt.Sprintf(`SELECT %s FROM rar_resource_types WHERE type = $1`, rarResourceTypeColumns)
	rt, err := scanRARResourceType(r.pool.QueryRow(ctx, query, typeName))
	if err != nil {
		return nil, fmt.Errorf("find rar resource type %q: %w", typeName, err)
	}
	return rt, nil
}

// ListResourceTypes returns all registered resource types.
func (r *PostgresRARRepository) ListResourceTypes(ctx context.Context) ([]*domain.RARResourceType, error) {
	query := fmt.Sprintf(`SELECT %s FROM rar_resource_types ORDER BY type`, rarResourceTypeColumns)
	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list rar resource types: %w", err)
	}
	defer rows.Close()

	var types []*domain.RARResourceType
	for rows.Next() {
		rt := &domain.RARResourceType{}
		if err := rows.Scan(
			&rt.ID, &rt.Type, &rt.Description,
			&rt.AllowedActions, &rt.AllowedDataTypes,
			&rt.CreatedAt, &rt.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan rar resource type: %w", err)
		}
		types = append(types, rt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rar resource types: %w", err)
	}
	return types, nil
}

// UpdateResourceType modifies a resource type's mutable fields.
func (r *PostgresRARRepository) UpdateResourceType(ctx context.Context, rt *domain.RARResourceType) (*domain.RARResourceType, error) {
	query := fmt.Sprintf(`
		UPDATE rar_resource_types
		SET description = $1, allowed_actions = $2, allowed_datatypes = $3, updated_at = $4
		WHERE id = $5
		RETURNING %s`, rarResourceTypeColumns)

	result, err := scanRARResourceType(r.pool.QueryRow(ctx, query,
		rt.Description, rt.AllowedActions, rt.AllowedDataTypes, time.Now().UTC(), rt.ID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("rar resource type %s: %w", rt.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update rar resource type: %w", err)
	}
	return result, nil
}

// DeleteResourceType removes a resource type (cascades to client associations).
func (r *PostgresRARRepository) DeleteResourceType(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM rar_resource_types WHERE id = $1`
	tag, err := r.pool.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("delete rar resource type %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("rar resource type %s: %w", id, ErrNotFound)
	}
	return nil
}

// AllowClientType grants a client permission to use a specific authorization type.
func (r *PostgresRARRepository) AllowClientType(ctx context.Context, clientID, resourceTypeID uuid.UUID) error {
	query := `INSERT INTO client_rar_allowed_types (client_id, resource_type_id) VALUES ($1, $2)`
	_, err := r.pool.Exec(ctx, query, clientID, resourceTypeID)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("client %s type %s: %w", clientID, resourceTypeID, ErrDuplicateClientRARType)
		}
		return fmt.Errorf("allow client rar type: %w", err)
	}
	return nil
}

// RevokeClientType removes a client's permission to use a specific authorization type.
func (r *PostgresRARRepository) RevokeClientType(ctx context.Context, clientID, resourceTypeID uuid.UUID) error {
	query := `DELETE FROM client_rar_allowed_types WHERE client_id = $1 AND resource_type_id = $2`
	tag, err := r.pool.Exec(ctx, query, clientID, resourceTypeID)
	if err != nil {
		return fmt.Errorf("revoke client rar type: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("client %s type %s: %w", clientID, resourceTypeID, ErrNotFound)
	}
	return nil
}

// ListClientAllowedTypes returns all resource types a client is allowed to use.
func (r *PostgresRARRepository) ListClientAllowedTypes(ctx context.Context, clientID uuid.UUID) ([]*domain.RARResourceType, error) {
	query := fmt.Sprintf(`
		SELECT %s FROM rar_resource_types rt
		INNER JOIN client_rar_allowed_types cat ON rt.id = cat.resource_type_id
		WHERE cat.client_id = $1
		ORDER BY rt.type`, rarResourceTypeColumns)

	rows, err := r.pool.Query(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("list client rar allowed types: %w", err)
	}
	defer rows.Close()

	var types []*domain.RARResourceType
	for rows.Next() {
		rt := &domain.RARResourceType{}
		if err := rows.Scan(
			&rt.ID, &rt.Type, &rt.Description,
			&rt.AllowedActions, &rt.AllowedDataTypes,
			&rt.CreatedAt, &rt.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan client rar allowed type: %w", err)
		}
		types = append(types, rt)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate client rar allowed types: %w", err)
	}
	return types, nil
}

// IsClientTypeAllowed checks whether a client is permitted to use the given authorization type.
func (r *PostgresRARRepository) IsClientTypeAllowed(ctx context.Context, clientID uuid.UUID, typeName string) (bool, error) {
	query := `
		SELECT EXISTS(
			SELECT 1 FROM client_rar_allowed_types cat
			INNER JOIN rar_resource_types rt ON rt.id = cat.resource_type_id
			WHERE cat.client_id = $1 AND rt.type = $2
		)`
	var allowed bool
	err := r.pool.QueryRow(ctx, query, clientID, typeName).Scan(&allowed)
	if err != nil {
		return false, fmt.Errorf("check client rar type allowed: %w", err)
	}
	return allowed, nil
}
