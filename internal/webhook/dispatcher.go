package webhook

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/storage"
)

// Dispatcher configuration constants.
const (
	DefaultBufferSize  = 1024
	DefaultWorkerCount = 4
	DeliveryTimeout    = 5 * time.Second
	MaxAttempts        = 3
	MaxResponseBodyLen = 1024
)

// RetryDelays defines the backoff delays for retry attempts (indexed by attempt-1).
// Attempt 1: 1s, Attempt 2: 5s, Attempt 3: 25s.
var RetryDelays = [MaxAttempts]time.Duration{
	1 * time.Second,
	5 * time.Second,
	25 * time.Second,
}

// HTTPDoer abstracts HTTP client for testing.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// deliveryTask is the internal work item sent through the channel.
type deliveryTask struct {
	webhook   *domain.Webhook
	event     domain.WebhookEvent
	attempt   int
	deliverAt time.Time // for retry scheduling
}

// Dispatcher delivers webhook events asynchronously using a buffered channel
// and worker pool. It implements httpserver.Closer for graceful shutdown.
type Dispatcher struct {
	repo              storage.WebhookRepository
	client            HTTPDoer
	logger            *zap.Logger
	ch                chan deliveryTask
	wg                sync.WaitGroup
	maxConsecFailures int
	retryDelays       [MaxAttempts]time.Duration
	closing           atomic.Bool
	stopOnce          sync.Once
	stopped           chan struct{}
}

// DispatcherOption configures the Dispatcher.
type DispatcherOption func(*Dispatcher)

// WithBufferSize sets the channel buffer size.
func WithBufferSize(size int) DispatcherOption {
	return func(d *Dispatcher) {
		if size > 0 {
			d.ch = make(chan deliveryTask, size)
		}
	}
}

// WithWorkerCount sets the number of worker goroutines.
func WithWorkerCount(count int) DispatcherOption {
	return func(d *Dispatcher) {
		if count > 0 {
			d.wg.Add(count)
			for range count {
				go d.worker()
			}
		}
	}
}

// WithHTTPClient overrides the default HTTP client.
func WithHTTPClient(client HTTPDoer) DispatcherOption {
	return func(d *Dispatcher) {
		d.client = client
	}
}

// WithMaxConsecutiveFailures sets the threshold for auto-disabling a webhook.
func WithMaxConsecutiveFailures(n int) DispatcherOption {
	return func(d *Dispatcher) {
		if n > 0 {
			d.maxConsecFailures = n
		}
	}
}

// WithRetryDelays overrides the default retry delay schedule.
func WithRetryDelays(delays [MaxAttempts]time.Duration) DispatcherOption {
	return func(d *Dispatcher) {
		d.retryDelays = delays
	}
}

// NewDispatcher creates a Dispatcher with the given options and starts workers.
func NewDispatcher(logger *zap.Logger, repo storage.WebhookRepository, opts ...DispatcherOption) *Dispatcher {
	d := &Dispatcher{
		repo:              repo,
		logger:            logger,
		ch:                make(chan deliveryTask, DefaultBufferSize),
		maxConsecFailures: domain.DefaultMaxConsecutiveFailures,
		retryDelays:       RetryDelays,
		stopped:           make(chan struct{}),
		client: &http.Client{
			Timeout: DeliveryTimeout,
		},
	}

	// Apply options (WithBufferSize must come before WithWorkerCount).
	for _, opt := range opts {
		opt(d)
	}

	// If no WithWorkerCount option was provided, start default workers.
	// Check if any workers were started by inspecting wg state indirectly.
	// Since wg is zero-value, we start default workers only if none were added.
	return d
}

// Start launches the default worker pool. Call this after NewDispatcher if
// WithWorkerCount was not used.
func (d *Dispatcher) Start(workerCount int) {
	if workerCount <= 0 {
		workerCount = DefaultWorkerCount
	}
	d.wg.Add(workerCount)
	for range workerCount {
		go d.worker()
	}
}

// Dispatch fans out a webhook event to all matching active webhooks.
func (d *Dispatcher) Dispatch(ctx context.Context, event domain.WebhookEvent) {
	webhooks, err := d.repo.GetActiveWebhooksForEvent(ctx, event.EventType)
	if err != nil {
		d.logger.Error("failed to get webhooks for event",
			zap.String("event_type", event.EventType),
			zap.Error(err),
		)
		return
	}

	for _, wh := range webhooks {
		task := deliveryTask{
			webhook:   wh,
			event:     event,
			attempt:   1,
			deliverAt: time.Now(),
		}
		select {
		case d.ch <- task:
		default:
			d.logger.Warn("webhook dispatch buffer full, event dropped",
				zap.String("webhook_id", wh.ID),
				zap.String("event_type", event.EventType),
			)
		}
	}
}

// worker processes delivery tasks from the channel.
func (d *Dispatcher) worker() {
	defer d.wg.Done()
	for task := range d.ch {
		// Respect retry delay scheduling.
		if delay := time.Until(task.deliverAt); delay > 0 {
			time.Sleep(delay)
		}
		d.deliver(task)
	}
}

// deliver executes a single HTTP POST to the webhook URL and records the result.
func (d *Dispatcher) deliver(task deliveryTask) {
	ctx := context.Background()
	wh := task.webhook
	payload := task.event.Payload

	// Create delivery record.
	now := time.Now().UTC()
	delivery := &domain.WebhookDelivery{
		ID:        uuid.New().String(),
		WebhookID: wh.ID,
		EventType: task.event.EventType,
		Payload:   payload,
		Status:    domain.DeliveryStatusPending,
		Attempt:   task.attempt,
		CreatedAt: now,
	}

	_, createErr := d.repo.CreateDelivery(ctx, delivery)
	if createErr != nil {
		d.logger.Error("failed to create delivery record",
			zap.String("webhook_id", wh.ID),
			zap.Error(createErr),
		)
	}

	// Sign payload.
	signature := Sign(wh.Secret, payload)

	// Build request.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, wh.URL, bytes.NewReader(payload))
	if err != nil {
		d.recordFailure(ctx, delivery, 0, err.Error(), 0)
		d.handleFailure(ctx, task)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Signature-256", signature)
	req.Header.Set("X-Webhook-ID", wh.ID)
	req.Header.Set("X-Webhook-Event", task.event.EventType)

	// Execute request and measure duration.
	start := time.Now()
	resp, err := d.client.Do(req)
	durationMs := int(time.Since(start).Milliseconds())

	if err != nil {
		d.recordFailure(ctx, delivery, 0, err.Error(), durationMs)
		d.handleFailure(ctx, task)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read truncated response body.
	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, int64(MaxResponseBodyLen)))
	respBody := string(bodyBytes)

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		d.recordSuccess(ctx, delivery, resp.StatusCode, respBody, durationMs)
		d.handleSuccess(ctx, wh.ID)
	} else {
		d.recordFailure(ctx, delivery, resp.StatusCode, respBody, durationMs)
		d.handleFailure(ctx, task)
	}
}

// recordSuccess updates the delivery record with a successful status.
func (d *Dispatcher) recordSuccess(ctx context.Context, del *domain.WebhookDelivery, statusCode int, body string, durationMs int) {
	now := time.Now().UTC()
	del.Status = domain.DeliveryStatusSuccess
	del.ResponseCode = statusCode
	del.ResponseBody = body
	del.DurationMs = durationMs
	del.DeliveredAt = &now

	if err := d.repo.UpdateDelivery(ctx, del); err != nil {
		d.logger.Error("failed to update delivery record",
			zap.String("delivery_id", del.ID),
			zap.Error(err),
		)
	}
}

// recordFailure updates the delivery record with a failed status.
func (d *Dispatcher) recordFailure(ctx context.Context, del *domain.WebhookDelivery, statusCode int, body string, durationMs int) {
	now := time.Now().UTC()
	del.ResponseCode = statusCode
	del.ResponseBody = body
	del.DurationMs = durationMs
	del.DeliveredAt = &now

	if del.Attempt >= MaxAttempts {
		del.Status = domain.DeliveryStatusAbandoned
	} else {
		del.Status = domain.DeliveryStatusRetrying
		nextRetry := now.Add(d.retryDelays[del.Attempt]) // attempt is 1-indexed, delays 0-indexed
		del.NextRetryAt = &nextRetry
	}

	if err := d.repo.UpdateDelivery(ctx, del); err != nil {
		d.logger.Error("failed to update delivery record",
			zap.String("delivery_id", del.ID),
			zap.Error(err),
		)
	}
}

// handleSuccess resets the failure count on successful delivery.
func (d *Dispatcher) handleSuccess(ctx context.Context, webhookID string) {
	if err := d.repo.ResetFailureCount(ctx, webhookID); err != nil {
		d.logger.Error("failed to reset failure count",
			zap.String("webhook_id", webhookID),
			zap.Error(err),
		)
	}
}

// handleFailure increments the failure count, auto-disables the webhook if
// threshold exceeded, and enqueues a retry if attempts remain.
func (d *Dispatcher) handleFailure(ctx context.Context, task deliveryTask) {
	count, err := d.repo.IncrementFailureCount(ctx, task.webhook.ID)
	if err != nil {
		d.logger.Error("failed to increment failure count",
			zap.String("webhook_id", task.webhook.ID),
			zap.Error(err),
		)
	}

	// Auto-disable after N consecutive failures.
	if count >= d.maxConsecFailures {
		if disableErr := d.repo.DisableWebhook(ctx, task.webhook.ID); disableErr != nil {
			d.logger.Error("failed to disable webhook",
				zap.String("webhook_id", task.webhook.ID),
				zap.Error(disableErr),
			)
		} else {
			d.logger.Warn("webhook auto-disabled due to consecutive failures",
				zap.String("webhook_id", task.webhook.ID),
				zap.Int("failure_count", count),
			)
		}
		return
	}

	// Schedule retry if attempts remain and dispatcher is not shutting down.
	if task.attempt < MaxAttempts && !d.closing.Load() {
		retry := deliveryTask{
			webhook:   task.webhook,
			event:     task.event,
			attempt:   task.attempt + 1,
			deliverAt: time.Now().Add(d.retryDelays[task.attempt]), // delays[1]=5s, delays[2]=25s
		}
		select {
		case d.ch <- retry:
			d.logger.Info("webhook delivery retry scheduled",
				zap.String("webhook_id", task.webhook.ID),
				zap.Int("attempt", retry.attempt),
			)
		default:
			d.logger.Warn("webhook retry buffer full, retry dropped",
				zap.String("webhook_id", task.webhook.ID),
			)
		}
	}
}

// Close signals all workers to finish and waits for them to drain.
// Implements httpserver.Closer.
func (d *Dispatcher) Close() error {
	d.stopOnce.Do(func() {
		d.closing.Store(true)
		close(d.ch)
		d.wg.Wait()
		close(d.stopped)
	})
	return nil
}

// Name returns the closer label for shutdown logging.
func (d *Dispatcher) Name() string { return "webhook-dispatcher" }

// Done returns a channel that is closed when the dispatcher has fully stopped.
func (d *Dispatcher) Done() <-chan struct{} { return d.stopped }

// compile-time assertion that Dispatcher satisfies the expected shape.
var _ interface {
	Name() string
	Close() error
} = (*Dispatcher)(nil)
