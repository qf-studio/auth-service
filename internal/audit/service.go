package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"go.uber.org/zap"
)

// Repository defines the persistence contract for audit events.
type Repository interface {
	Insert(ctx context.Context, event *AuditEvent) error
}

// Service provides asynchronous audit event logging through a buffered channel.
// Events are written to a channel and consumed by a background worker that
// persists them via the Repository. Call Close to flush remaining events.
type Service struct {
	repo    Repository
	logger  *zap.Logger
	eventCh chan *AuditEvent
	done    chan struct{}
	wg      sync.WaitGroup
}

// DefaultBufferSize is the default capacity of the event channel.
const DefaultBufferSize = 1024

// NewService creates a new audit Service with the given buffer size.
// The background worker starts immediately. Call Close to stop it.
func NewService(repo Repository, logger *zap.Logger, bufferSize int) *Service {
	if bufferSize <= 0 {
		bufferSize = DefaultBufferSize
	}

	s := &Service{
		repo:    repo,
		logger:  logger,
		eventCh: make(chan *AuditEvent, bufferSize),
		done:    make(chan struct{}),
	}

	s.wg.Add(1)
	go s.worker()

	return s
}

// LogEvent enqueues an audit event for asynchronous persistence.
// Returns an error if the event is nil, missing required fields,
// or the service has been closed.
func (s *Service) LogEvent(event *AuditEvent) error {
	if err := s.validate(event); err != nil {
		return fmt.Errorf("audit: invalid event: %w", err)
	}

	// Check closed state first to avoid non-deterministic select.
	select {
	case <-s.done:
		return errors.New("audit: service closed")
	default:
	}

	select {
	case s.eventCh <- event:
		return nil
	case <-s.done:
		return errors.New("audit: service closed")
	}
}

// Close signals the worker to stop and waits for all queued events
// to be flushed. It is safe to call multiple times.
func (s *Service) Close() {
	select {
	case <-s.done:
		// Already closed.
		return
	default:
		close(s.done)
	}

	// Drain remaining events.
	s.wg.Wait()
}

// validate checks that an event has the minimum required fields.
func (s *Service) validate(event *AuditEvent) error {
	if event == nil {
		return errors.New("event must not be nil")
	}
	if event.ID == "" {
		return errors.New("event ID is required")
	}
	if event.EventType == "" {
		return errors.New("event type is required")
	}
	if event.Outcome == "" {
		return errors.New("outcome is required")
	}
	if event.Timestamp.IsZero() {
		return errors.New("timestamp is required")
	}
	return nil
}

// worker is the background goroutine that reads events from the channel
// and persists them. It exits when the done channel is closed and
// all remaining events in the channel have been flushed.
func (s *Service) worker() {
	defer s.wg.Done()

	for {
		select {
		case event := <-s.eventCh:
			if event != nil {
				s.persist(event)
			}
		case <-s.done:
			// Drain remaining events in the channel.
			s.drain()
			return
		}
	}
}

// drain flushes all remaining events from the channel.
func (s *Service) drain() {
	for {
		select {
		case event := <-s.eventCh:
			if event != nil {
				s.persist(event)
			}
		default:
			return
		}
	}
}

// persist writes a single event to the repository.
// Errors are logged but do not propagate — audit failures must not
// break the primary request flow.
func (s *Service) persist(event *AuditEvent) {
	ctx := context.Background()
	if err := s.repo.Insert(ctx, event); err != nil {
		s.logger.Error("failed to persist audit event",
			zap.String("event_id", event.ID),
			zap.String("event_type", string(event.EventType)),
			zap.Error(err),
		)
	}
}
