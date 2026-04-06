package storage

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

// WebhookRepository defines persistence operations for webhooks and delivery logs.
type WebhookRepository interface {
	// CreateWebhook inserts a new webhook and returns the created record.
	CreateWebhook(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)

	// GetWebhook retrieves a webhook by ID. Returns ErrNotFound if absent.
	GetWebhook(ctx context.Context, id string) (*domain.Webhook, error)

	// ListWebhooks returns all webhooks, optionally filtered by active status.
	ListWebhooks(ctx context.Context, activeOnly bool) ([]*domain.Webhook, error)

	// UpdateWebhook updates a webhook's mutable fields.
	UpdateWebhook(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error)

	// DeleteWebhook removes a webhook by ID. Returns ErrNotFound if absent.
	DeleteWebhook(ctx context.Context, id string) error

	// IncrementFailureCount atomically increments the failure count. Returns the new count.
	IncrementFailureCount(ctx context.Context, id string) (int, error)

	// ResetFailureCount sets the failure count to zero.
	ResetFailureCount(ctx context.Context, id string) error

	// DisableWebhook sets active=false for the given webhook.
	DisableWebhook(ctx context.Context, id string) error

	// GetActiveWebhooksForEvent returns all active webhooks subscribed to the given event type.
	GetActiveWebhooksForEvent(ctx context.Context, eventType string) ([]*domain.Webhook, error)

	// CreateDelivery inserts a delivery log record.
	CreateDelivery(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error)

	// UpdateDelivery updates a delivery record (status, response, timing).
	UpdateDelivery(ctx context.Context, d *domain.WebhookDelivery) error
}

// PostgresWebhookRepository implements WebhookRepository using pgx against PostgreSQL.
type PostgresWebhookRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebhookRepository creates a new PostgreSQL-backed webhook repository.
func NewPostgresWebhookRepository(pool *pgxpool.Pool) *PostgresWebhookRepository {
	return &PostgresWebhookRepository{pool: pool}
}

// CreateWebhook inserts a new webhook row.
func (r *PostgresWebhookRepository) CreateWebhook(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	query := `
		INSERT INTO webhooks (id, url, secret, event_types, active, failure_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, url, secret, event_types, active, failure_count, created_at, updated_at`

	out := &domain.Webhook{}
	err := r.pool.QueryRow(ctx, query,
		wh.ID, wh.URL, wh.Secret, wh.EventTypes,
		wh.Active, wh.FailureCount, wh.CreatedAt, wh.UpdatedAt,
	).Scan(
		&out.ID, &out.URL, &out.Secret, &out.EventTypes,
		&out.Active, &out.FailureCount, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create webhook: %w", err)
	}
	return out, nil
}

// GetWebhook retrieves a webhook by ID.
func (r *PostgresWebhookRepository) GetWebhook(ctx context.Context, id string) (*domain.Webhook, error) {
	query := `
		SELECT id, url, secret, event_types, active, failure_count, created_at, updated_at
		FROM webhooks WHERE id = $1`

	wh := &domain.Webhook{}
	err := r.pool.QueryRow(ctx, query, id).Scan(
		&wh.ID, &wh.URL, &wh.Secret, &wh.EventTypes,
		&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("get webhook: %w", err)
	}
	return wh, nil
}

// ListWebhooks returns webhooks, optionally filtered to active only.
func (r *PostgresWebhookRepository) ListWebhooks(ctx context.Context, activeOnly bool) ([]*domain.Webhook, error) {
	query := `SELECT id, url, secret, event_types, active, failure_count, created_at, updated_at FROM webhooks`
	if activeOnly {
		query += ` WHERE active = true`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		wh := &domain.Webhook{}
		if err := rows.Scan(
			&wh.ID, &wh.URL, &wh.Secret, &wh.EventTypes,
			&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, rows.Err()
}

// UpdateWebhook updates a webhook's mutable fields.
func (r *PostgresWebhookRepository) UpdateWebhook(ctx context.Context, wh *domain.Webhook) (*domain.Webhook, error) {
	query := `
		UPDATE webhooks
		SET url = $2, secret = $3, event_types = $4, active = $5, updated_at = $6
		WHERE id = $1
		RETURNING id, url, secret, event_types, active, failure_count, created_at, updated_at`

	out := &domain.Webhook{}
	err := r.pool.QueryRow(ctx, query,
		wh.ID, wh.URL, wh.Secret, wh.EventTypes, wh.Active, wh.UpdatedAt,
	).Scan(
		&out.ID, &out.URL, &out.Secret, &out.EventTypes,
		&out.Active, &out.FailureCount, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("update webhook: %w", err)
	}
	return out, nil
}

// DeleteWebhook removes a webhook by ID.
func (r *PostgresWebhookRepository) DeleteWebhook(ctx context.Context, id string) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM webhooks WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete webhook: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// IncrementFailureCount atomically increments the failure count and returns the new value.
func (r *PostgresWebhookRepository) IncrementFailureCount(ctx context.Context, id string) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`UPDATE webhooks SET failure_count = failure_count + 1, updated_at = now() WHERE id = $1 RETURNING failure_count`,
		id,
	).Scan(&count)
	if err != nil {
		if err == pgx.ErrNoRows {
			return 0, ErrNotFound
		}
		return 0, fmt.Errorf("increment failure count: %w", err)
	}
	return count, nil
}

// ResetFailureCount sets the failure count to zero.
func (r *PostgresWebhookRepository) ResetFailureCount(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE webhooks SET failure_count = 0, updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("reset failure count: %w", err)
	}
	return nil
}

// DisableWebhook sets active=false for the given webhook.
func (r *PostgresWebhookRepository) DisableWebhook(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE webhooks SET active = false, updated_at = now() WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("disable webhook: %w", err)
	}
	return nil
}

// GetActiveWebhooksForEvent returns active webhooks subscribed to the given event type.
func (r *PostgresWebhookRepository) GetActiveWebhooksForEvent(ctx context.Context, eventType string) ([]*domain.Webhook, error) {
	query := `
		SELECT id, url, secret, event_types, active, failure_count, created_at, updated_at
		FROM webhooks
		WHERE active = true AND $1 = ANY(event_types)
		ORDER BY created_at`

	rows, err := r.pool.Query(ctx, query, eventType)
	if err != nil {
		return nil, fmt.Errorf("get webhooks for event: %w", err)
	}
	defer rows.Close()

	var webhooks []*domain.Webhook
	for rows.Next() {
		wh := &domain.Webhook{}
		if err := rows.Scan(
			&wh.ID, &wh.URL, &wh.Secret, &wh.EventTypes,
			&wh.Active, &wh.FailureCount, &wh.CreatedAt, &wh.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, wh)
	}
	return webhooks, rows.Err()
}

// CreateDelivery inserts a webhook delivery log record.
func (r *PostgresWebhookRepository) CreateDelivery(ctx context.Context, d *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	query := `
		INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, response_code, response_body, attempt, next_retry_at, delivered_at, duration_ms, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING id, webhook_id, event_type, payload, status, response_code, response_body, attempt, next_retry_at, delivered_at, duration_ms, created_at`

	out := &domain.WebhookDelivery{}
	err := r.pool.QueryRow(ctx, query,
		d.ID, d.WebhookID, d.EventType, d.Payload, d.Status,
		d.ResponseCode, d.ResponseBody, d.Attempt, d.NextRetryAt,
		d.DeliveredAt, d.DurationMs, d.CreatedAt,
	).Scan(
		&out.ID, &out.WebhookID, &out.EventType, &out.Payload, &out.Status,
		&out.ResponseCode, &out.ResponseBody, &out.Attempt, &out.NextRetryAt,
		&out.DeliveredAt, &out.DurationMs, &out.CreatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("create delivery: %w", err)
	}
	return out, nil
}

// UpdateDelivery updates a delivery record after an attempt.
func (r *PostgresWebhookRepository) UpdateDelivery(ctx context.Context, d *domain.WebhookDelivery) error {
	query := `
		UPDATE webhook_deliveries
		SET status = $2, response_code = $3, response_body = $4,
		    delivered_at = $5, duration_ms = $6, next_retry_at = $7
		WHERE id = $1`

	_, err := r.pool.Exec(ctx, query,
		d.ID, d.Status, d.ResponseCode, d.ResponseBody,
		d.DeliveredAt, d.DurationMs, d.NextRetryAt,
	)
	if err != nil {
		return fmt.Errorf("update delivery: %w", err)
	}
	return nil
}
