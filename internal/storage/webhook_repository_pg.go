package storage

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/qf-studio/auth-service/internal/domain"
)

const webhookColumns = `id, url, secret, event_types, active, failure_count, created_at, updated_at`
const deliveryColumns = `id, webhook_id, event_type, payload, status, response_code, attempt, next_retry_at, delivered_at, created_at`

// PostgresWebhookRepository implements WebhookRepository using PostgreSQL.
type PostgresWebhookRepository struct {
	pool *pgxpool.Pool
}

// NewPostgresWebhookRepository creates a new PostgresWebhookRepository.
func NewPostgresWebhookRepository(pool *pgxpool.Pool) *PostgresWebhookRepository {
	return &PostgresWebhookRepository{pool: pool}
}

func scanWebhook(row pgx.Row) (*domain.Webhook, error) {
	w := &domain.Webhook{}
	err := row.Scan(&w.ID, &w.URL, &w.Secret, &w.EventTypes, &w.Active, &w.FailureCount, &w.CreatedAt, &w.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return w, nil
}

func scanDelivery(row pgx.Row) (*domain.WebhookDelivery, error) {
	d := &domain.WebhookDelivery{}
	err := row.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.ResponseCode, &d.Attempt, &d.NextRetryAt, &d.DeliveredAt, &d.CreatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	return d, nil
}

// CreateWebhook inserts a new webhook.
func (r *PostgresWebhookRepository) CreateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error) {
	query := fmt.Sprintf(`
		INSERT INTO webhooks (id, url, secret, event_types, active, failure_count, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING %s`, webhookColumns)

	out, err := scanWebhook(r.pool.QueryRow(ctx, query,
		webhook.ID, webhook.URL, webhook.Secret, webhook.EventTypes,
		webhook.Active, webhook.FailureCount, webhook.CreatedAt, webhook.UpdatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert webhook: %w", err)
	}
	return out, nil
}

// GetWebhook retrieves a webhook by ID.
func (r *PostgresWebhookRepository) GetWebhook(ctx context.Context, id string) (*domain.Webhook, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhooks WHERE id = $1`, webhookColumns)
	out, err := scanWebhook(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get webhook %s: %w", id, err)
	}
	return out, nil
}

// ListWebhooks returns all webhooks, optionally filtering by active status.
func (r *PostgresWebhookRepository) ListWebhooks(ctx context.Context, activeOnly bool) ([]domain.Webhook, error) {
	var query string
	var rows pgx.Rows
	var err error

	if activeOnly {
		query = fmt.Sprintf(`SELECT %s FROM webhooks WHERE active = true ORDER BY created_at`, webhookColumns)
		rows, err = r.pool.Query(ctx, query)
	} else {
		query = fmt.Sprintf(`SELECT %s FROM webhooks ORDER BY created_at`, webhookColumns)
		rows, err = r.pool.Query(ctx, query)
	}
	if err != nil {
		return nil, fmt.Errorf("list webhooks: %w", err)
	}
	defer rows.Close()

	var webhooks []domain.Webhook
	for rows.Next() {
		var w domain.Webhook
		if err := rows.Scan(&w.ID, &w.URL, &w.Secret, &w.EventTypes, &w.Active, &w.FailureCount, &w.CreatedAt, &w.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan webhook: %w", err)
		}
		webhooks = append(webhooks, w)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate webhooks: %w", err)
	}
	return webhooks, nil
}

// UpdateWebhook updates a webhook's mutable fields.
func (r *PostgresWebhookRepository) UpdateWebhook(ctx context.Context, webhook *domain.Webhook) (*domain.Webhook, error) {
	query := fmt.Sprintf(`
		UPDATE webhooks
		SET url = $1, secret = $2, event_types = $3, active = $4, updated_at = $5
		WHERE id = $6
		RETURNING %s`, webhookColumns)

	out, err := scanWebhook(r.pool.QueryRow(ctx, query,
		webhook.URL, webhook.Secret, webhook.EventTypes, webhook.Active, webhook.UpdatedAt, webhook.ID,
	))
	if err != nil {
		return nil, fmt.Errorf("update webhook %s: %w", webhook.ID, err)
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
		return fmt.Errorf("webhook %s: %w", id, ErrNotFound)
	}
	return nil
}

// CreateDelivery inserts a new webhook delivery record.
func (r *PostgresWebhookRepository) CreateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) (*domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`
		INSERT INTO webhook_deliveries (id, webhook_id, event_type, payload, status, response_code, attempt, next_retry_at, delivered_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING %s`, deliveryColumns)

	out, err := scanDelivery(r.pool.QueryRow(ctx, query,
		delivery.ID, delivery.WebhookID, delivery.EventType, delivery.Payload,
		delivery.Status, delivery.ResponseCode, delivery.Attempt,
		delivery.NextRetryAt, delivery.DeliveredAt, delivery.CreatedAt,
	))
	if err != nil {
		return nil, fmt.Errorf("insert delivery: %w", err)
	}
	return out, nil
}

// GetDelivery retrieves a delivery by ID.
func (r *PostgresWebhookRepository) GetDelivery(ctx context.Context, id string) (*domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE id = $1`, deliveryColumns)
	out, err := scanDelivery(r.pool.QueryRow(ctx, query, id))
	if err != nil {
		return nil, fmt.Errorf("get delivery %s: %w", id, err)
	}
	return out, nil
}

// ListDeliveriesByWebhook returns all deliveries for a given webhook.
func (r *PostgresWebhookRepository) ListDeliveriesByWebhook(ctx context.Context, webhookID string) ([]domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE webhook_id = $1 ORDER BY created_at DESC`, deliveryColumns)
	rows, err := r.pool.Query(ctx, query, webhookID)
	if err != nil {
		return nil, fmt.Errorf("list deliveries for webhook %s: %w", webhookID, err)
	}
	defer rows.Close()

	var deliveries []domain.WebhookDelivery
	for rows.Next() {
		var d domain.WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.ResponseCode, &d.Attempt, &d.NextRetryAt, &d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deliveries: %w", err)
	}
	return deliveries, nil
}

// ListDeliveriesByStatus returns all deliveries with a given status.
func (r *PostgresWebhookRepository) ListDeliveriesByStatus(ctx context.Context, status string) ([]domain.WebhookDelivery, error) {
	query := fmt.Sprintf(`SELECT %s FROM webhook_deliveries WHERE status = $1 ORDER BY created_at`, deliveryColumns)
	rows, err := r.pool.Query(ctx, query, status)
	if err != nil {
		return nil, fmt.Errorf("list deliveries by status %s: %w", status, err)
	}
	defer rows.Close()

	var deliveries []domain.WebhookDelivery
	for rows.Next() {
		var d domain.WebhookDelivery
		if err := rows.Scan(&d.ID, &d.WebhookID, &d.EventType, &d.Payload, &d.Status, &d.ResponseCode, &d.Attempt, &d.NextRetryAt, &d.DeliveredAt, &d.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan delivery: %w", err)
		}
		deliveries = append(deliveries, d)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate deliveries: %w", err)
	}
	return deliveries, nil
}

// UpdateDelivery updates a delivery record (status, response_code, attempt, next_retry_at, delivered_at).
func (r *PostgresWebhookRepository) UpdateDelivery(ctx context.Context, delivery *domain.WebhookDelivery) error {
	query := `
		UPDATE webhook_deliveries
		SET status = $1, response_code = $2, attempt = $3, next_retry_at = $4, delivered_at = $5
		WHERE id = $6`

	tag, err := r.pool.Exec(ctx, query,
		delivery.Status, delivery.ResponseCode, delivery.Attempt,
		delivery.NextRetryAt, delivery.DeliveredAt, delivery.ID,
	)
	if err != nil {
		return fmt.Errorf("update delivery %s: %w", delivery.ID, err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("delivery %s: %w", delivery.ID, ErrNotFound)
	}
	return nil
}

// IncrementFailureCount atomically increments the failure count and returns the new value.
func (r *PostgresWebhookRepository) IncrementFailureCount(ctx context.Context, webhookID string) (int, error) {
	var count int
	err := r.pool.QueryRow(ctx,
		`UPDATE webhooks SET failure_count = failure_count + 1, updated_at = now() WHERE id = $1 RETURNING failure_count`,
		webhookID,
	).Scan(&count)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, fmt.Errorf("webhook %s: %w", webhookID, ErrNotFound)
		}
		return 0, fmt.Errorf("increment failure count: %w", err)
	}
	return count, nil
}

// ResetFailureCount sets the failure count back to zero.
func (r *PostgresWebhookRepository) ResetFailureCount(ctx context.Context, webhookID string) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE webhooks SET failure_count = 0, updated_at = now() WHERE id = $1`,
		webhookID,
	)
	if err != nil {
		return fmt.Errorf("reset failure count: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("webhook %s: %w", webhookID, ErrNotFound)
	}
	return nil
}
