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

// WebhookRepository defines persistence operations for webhook management.
type WebhookRepository interface {
	List(ctx context.Context, tenantID uuid.UUID, limit, offset int, activeOnly bool) ([]*domain.Webhook, int, error)
	FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Webhook, error)
	FindActiveByEventType(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*domain.Webhook, error)
	Create(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)
	Update(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)
	Delete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	IncrementFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	ResetFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
	Disable(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error
}

// WebhookDeliveryRepository defines persistence operations for webhook delivery logs.
type WebhookDeliveryRepository interface {
	List(ctx context.Context, tenantID uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error)
	FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error)
	Create(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error)
	UpdateStatus(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error
	FindPendingRetries(ctx context.Context, tenantID uuid.UUID, before time.Time, limit int) ([]*domain.WebhookDelivery, error)
}

const webhookColumns = `id, tenant_id, url, secret_hash, event_types, active, failure_count, created_at, updated_at`

func scanWebhook(row pgx.Row) (*domain.Webhook, error) {
	wh := &domain.Webhook{}
	err := row.Scan(
		&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.EventTypes,
		&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return wh, nil
}

const webhookDeliveryColumns = `id, tenant_id, webhook_id, event_type, payload, status, response_code, response_body, attempt, next_retry_at, delivered_at, created_at`

func scanWebhookDelivery(row pgx.Row) (*domain.WebhookDelivery, error) {
	d := &domain.WebhookDelivery{}
	err := row.Scan(
		&d.ID, &d.TenantID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status,
		&d.ResponseCode, &d.ResponseBody, &d.Attempt, &d.NextRetryAt,
		&d.DeliveredAt, &d.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return d, nil
}

// PostgresWebhookRepository implements WebhookRepository using PostgreSQL.
type PostgresWebhookRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebhookRepository creates a new PostgreSQL-backed webhook repository.
func NewPostgresWebhookRepository(pool *pgxpool.Pool) *PostgresWebhookRepository {
	return &PostgresWebhookRepository{pool: pool}
}

// List returns a paginated list of webhooks for a tenant, optionally filtered to active only.
func (r *PostgresWebhookRepository) List(ctx context.Context, tenantID uuid.UUID, limit, offset int, activeOnly bool) ([]*domain.Webhook, int, error) {
	whereClause := "WHERE tenant_id = $1"
	args := []interface{}{tenantID}

	if activeOnly {
		whereClause += " AND active = true"
	}

	countQuery := fmt.Sprintf(`SELECT COUNT(*) FROM webhooks %s`, whereClause)
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count webhooks: %w", err)
	}

	args = append(args, limit, offset)
	query := fmt.Sprintf(`SELECT %s FROM webhooks %s ORDER BY created_at DESC LIMIT $%d OFFSET $%d`,
		webhookColumns, whereClause, len(args)-1, len(args))
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		wh := &domain.Webhook{}
		if err := rows.Scan(
			&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.EventTypes,
			&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, wh)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate webhooks: %w", err)
	}

	return webhooks, total, nil
}

// FindByID retrieves a webhook by primary key.
func (r *PostgresWebhookRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE id = $1 AND tenant_id = $2`, webhookColumns)
	wh, err := scanWebhook(r.pool.QueryRow(ctx, query, id, tenantID))
	if err != nil {
		return nil, fmt.Errorf("find webhook %s: %w", id, err)
	}
	return wh, nil
}

// FindActiveByEventType returns all active webhooks subscribed to a given event type for a tenant.
func (r *PostgresWebhookRepository) FindActiveByEventType(ctx context.Context, tenantID uuid.UUID, eventType string) ([]*domain.Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE active = true AND $1 = ANY(event_types) AND tenant_id = $2`, webhookColumns)
	rows, err := r.pool.Query(ctx, query, eventType, tenantID)
	if err != nil {
		return nil, fmt.Errorf("find webhooks by event type: %w", err)
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		wh := &domain.Webhook{}
		if err := rows.Scan(
			&wh.ID, &wh.TenantID, &wh.URL, &wh.SecretHash, &wh.EventTypes,
			&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, wh)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhooks: %w", err)
	}

	return webhooks, nil
}

// Create inserts a new webhook.
func (r *PostgresWebhookRepository) Create(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	query := fmt.Sprintf(`
		INSERT INTO webhooks (id, tenant_id, url, secret_hash, event_types, active, failure_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING %s`, webhookColumns)

	result, err := scanWebhook(r.pool.QueryRow(ctx, query,
		wh.ID, wh.TenantID, wh.URL, wh.SecretHash, wh.EventTypes,
		wh.Active, wh.FailureCount, wh.CreatedAt, wh.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert webhook: %w", err)
	}
	return result, nil
}

// Update modifies mutable fields of a webhook (url, event_types, active).
func (r *PostgresWebhookRepository) Update(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	query := fmt.Sprintf(`
		UPDATE webhooks SET url = $1, event_types = $2, active = $3, updated_at = $4
		WHERE id = $5 AND tenant_id = $6
		RETURNING %s`, webhookColumns)

	result, err := scanWebhook(r.pool.QueryRow(ctx, query,
		wh.URL, wh.EventTypes, wh.Active, time.Now().UTC(), wh.ID, wh.TenantID,
	))
	if err != nil {
		if errors.Is(err, ErrNotFound) {
			return nil, fmt.Errorf("webhook %s: %w", wh.ID, ErrNotFound)
		}
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	return result, nil
}

// Delete removes a webhook by ID.
func (r *PostgresWebhookRepository) Delete(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2`
	tag, err := r.pool.Exec(ctx, query, id, tenantID)
	if err != nil {
		return fmt.Errorf("delete webhook %s: %w", id, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhook %s: %w", id, ErrNotFound)
	}
	return nil
}

// IncrementFailureCount increments the failure counter for a webhook.
func (r *PostgresWebhookRepository) IncrementFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `UPDATE webhooks SET failure_count = failure_count + 1, updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return fmt.Errorf("increment webhook failure count: %w", err)
	}
	return nil
}

// ResetFailureCount resets the failure counter for a webhook to zero.
func (r *PostgresWebhookRepository) ResetFailureCount(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `UPDATE webhooks SET failure_count = 0, updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return fmt.Errorf("reset webhook failure count: %w", err)
	}
	return nil
}

// Disable sets a webhook to inactive.
func (r *PostgresWebhookRepository) Disable(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) error {
	query := `UPDATE webhooks SET active = false, updated_at = $1 WHERE id = $2 AND tenant_id = $3`
	_, err := r.pool.Exec(ctx, query, time.Now().UTC(), id, tenantID)
	if err != nil {
		return fmt.Errorf("disable webhook: %w", err)
	}
	return nil
}

// PostgresWebhookDeliveryRepository implements WebhookDeliveryRepository using PostgreSQL.
type PostgresWebhookDeliveryRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebhookDeliveryRepository creates a new PostgreSQL-backed webhook delivery repository.
func NewPostgresWebhookDeliveryRepository(pool *pgxpool.Pool) *PostgresWebhookDeliveryRepository {
	return &PostgresWebhookDeliveryRepository{pool: pool}
}

// List returns a paginated list of deliveries for a given webhook within a tenant.
func (r *PostgresWebhookDeliveryRepository) List(ctx context.Context, tenantID uuid.UUID, webhookID uuid.UUID, limit, offset int) ([]*domain.WebhookDelivery, int, error) {
	countQuery := `SELECT COUNT(*) FROM webhook_deliveries WHERE webhook_id = $1 AND tenant_id = $2`
	var total int
	if err := r.pool.QueryRow(ctx, countQuery, webhookID, tenantID).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("count webhook deliveries: %w", err)
	}

	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE webhook_id = $1 AND tenant_id = $2 ORDER BY created_at DESC LIMIT $3 OFFSET $4`,
		webhookDeliveryColumns)
	rows, err := r.pool.Query(ctx, query, webhookID, tenantID, limit, offset)
	if err != nil {
		return nil, 0, fmt.Errorf("list webhook deliveries: %w", err)
	}
	defer rows.Close()

	var deliveries []*domain.WebhookDelivery
	for rows.Next() {
		d := &domain.WebhookDelivery{}
		if err := rows.Scan(
			&d.ID, &d.TenantID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status,
			&d.ResponseCode, &d.ResponseBody, &d.Attempt, &d.NextRetryAt,
			&d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, 0, fmt.Errorf("scan webhook delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterate webhook deliveries: %w", err)
	}

	return deliveries, total, nil
}

// FindByID retrieves a webhook delivery by primary key.
func (r *PostgresWebhookDeliveryRepository) FindByID(ctx context.Context, tenantID uuid.UUID, id uuid.UUID) (*domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE id = $1 AND tenant_id = $2`, webhookDeliveryColumns)
	d, err := scanWebhookDelivery(r.pool.QueryRow(ctx, query, id, tenantID))
	if err != nil {
		return nil, fmt.Errorf("find webhook delivery %s: %w", id, err)
	}
	return d, nil
}

// Create inserts a new webhook delivery record.
func (r *PostgresWebhookDeliveryRepository) Create(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`
		INSERT INTO webhook_deliveries (id, tenant_id, webhook_id, event_type, payload, status, response_code, response_body, attempt, next_retry_at, delivered_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING %s`, webhookDeliveryColumns)

	result, err := scanWebhookDelivery(r.pool.QueryRow(ctx, query,
		d.ID, d.TenantID, d.WebhookID, d.EventType, d.Payload, d.Status,
		d.ResponseCode, d.ResponseBody, d.Attempt, d.NextRetryAt,
		d.DeliveredAt, d.CreatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert webhook delivery: %w", err)
	}
	return result, nil
}

// UpdateStatus updates the status and response details of a delivery.
func (r *PostgresWebhookDeliveryRepository) UpdateStatus(ctx context.Context, tenantID uuid.UUID, id uuid.UUID, status string, responseCode *int, responseBody *string, deliveredAt *time.Time) error {
	query := `UPDATE webhook_deliveries SET status = $1, response_code = $2, response_body = $3, delivered_at = $4 WHERE id = $5 AND tenant_id = $6`
	_, err := r.pool.Exec(ctx, query, status, responseCode, responseBody, deliveredAt, id, tenantID)
	if err != nil {
		return fmt.Errorf("update webhook delivery status: %w", err)
	}
	return nil
}

// FindPendingRetries returns deliveries with status 'pending' and next_retry_at before the given time.
func (r *PostgresWebhookDeliveryRepository) FindPendingRetries(ctx context.Context, tenantID uuid.UUID, before time.Time, limit int) ([]*domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE status = 'pending' AND next_retry_at IS NOT NULL AND next_retry_at <= $1 AND tenant_id = $2 ORDER BY next_retry_at ASC LIMIT $3`,
		webhookDeliveryColumns)
	rows, err := r.pool.Query(ctx, query, before, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("find pending retries: %w", err)
	}
	defer rows.Close()

	var deliveries []*domain.WebhookDelivery
	for rows.Next() {
		d := &domain.WebhookDelivery{}
		if err := rows.Scan(
			&d.ID, &d.TenantID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status,
			&d.ResponseCode, &d.ResponseBody, &d.Attempt, &d.NextRetryAt,
			&d.DeliveredAt, &d.CreatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan pending delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate pending deliveries: %w", err)
	}

	return deliveries, nil
}
