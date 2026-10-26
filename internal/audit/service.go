package audit

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"

	"github.com/qf-studio/auth-service/internal/domain"
)

// Sink persists batches of audit events (e.g. to the audit_logs table).
type Sink interface {
	// InsertBatch stores all events atomically.
	InsertBatch(ctx context.Context, events []Event) error
	// DeleteOlderThan removes events created before cutoff and returns the
	// number of rows deleted.
	DeleteOlderThan(ctx context.Context, cutoff time.Time) (int64, error)
}

// DropRecorder counts audit events that were not persisted.
type DropRecorder interface {
	RecordAuditDropped(reason string, n int)
}

// Reasons reported to DropRecorder.
const (
	DropReasonBufferFull = "buffer_full" // buffer was full; event only reached the warn log
	DropReasonSinkError  = "sink_error"  // persistence failed; event only reached the zap log
)

// Defaults for Options.
const (
	DefaultBatchSize     = 100
	DefaultFlushInterval = time.Second
	flushTimeout         = 10 * time.Second
	retentionInterval    = 24 * time.Hour
)

// Options configures optional persistence for a Service. The zero value gives
// the zap-only behavior.
type Options struct {
	Sink          Sink          // nil: events are only logged to zap
	Drops         DropRecorder  // nil: drops are not counted
	BatchSize     int           // max events per insert (default 100)
	FlushInterval time.Duration // max time an event waits for a full batch (default 1s)
	RetentionDays int           // rows older than this are deleted daily; <= 0 disables
}

// Service implements EventLogger with an async buffered channel. Events are
// always written to zap and, when a Sink is configured, persisted in batches.
// Pending events are flushed on Close so nothing is lost during graceful
// termination.
type Service struct {
	logger *zap.Logger
	ch     chan Event
	done   chan struct{}
	opts   Options

	stop        chan struct{} // closed by Close to stop the retention loop
	retentionWG sync.WaitGroup
	now         func() time.Time
}

// NewService creates an audit Service that only logs to zap.
// Events exceeding the buffer are logged and dropped (non-blocking).
func NewService(logger *zap.Logger, bufferSize int) *Service {
	return NewServiceWithOptions(logger, bufferSize, Options{})
}

// NewServiceWithOptions creates an audit Service with the given buffer size
// and persistence options.
func NewServiceWithOptions(logger *zap.Logger, bufferSize int, opts Options) *Service {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	if opts.BatchSize <= 0 {
		opts.BatchSize = DefaultBatchSize
	}
	if opts.FlushInterval <= 0 {
		opts.FlushInterval = DefaultFlushInterval
	}
	s := &Service{
		logger: logger,
		ch:     make(chan Event, bufferSize),
		done:   make(chan struct{}),
		opts:   opts,
		stop:   make(chan struct{}),
		now:    time.Now,
	}
	go s.drain()
	if opts.Sink != nil && opts.RetentionDays > 0 {
		s.retentionWG.Add(1)
		go s.retentionLoop()
	}
	return s
}

// LogEvent enqueues an audit event. It is non-blocking; if the buffer is full
// the event is logged at warn level, counted and dropped.
func (s *Service) LogEvent(ctx context.Context, event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if event.TenantID == uuid.Nil {
		event.TenantID = domain.TenantIDFromContext(ctx)
	}
	select {
	case s.ch <- event:
	default:
		s.logger.Warn("audit buffer full, event dropped",
			zap.String("event_type", event.Type),
			zap.String("actor_id", event.ActorID),
		)
		s.recordDropped(DropReasonBufferFull, 1)
	}
}

// Close signals the drain goroutine to flush remaining events and waits for
// completion. Implements httpserver.Closer semantics.
func (s *Service) Close() error {
	close(s.stop)
	close(s.ch)
	<-s.done
	s.retentionWG.Wait()
	return nil
}

// Name returns the closer label for logging.
func (s *Service) Name() string { return "audit" }

func (s *Service) recordDropped(reason string, n int) {
	if s.opts.Drops != nil {
		s.opts.Drops.RecordAuditDropped(reason, n)
	}
}

// drain reads events from the channel, logs each via zap and persists them to
// the Sink in batches of up to BatchSize events or FlushInterval, whichever
// comes first.
func (s *Service) drain() {
	defer close(s.done)

	batch := make([]Event, 0, s.opts.BatchSize)
	var tick <-chan time.Time
	if s.opts.Sink != nil {
		t := time.NewTicker(s.opts.FlushInterval)
		defer t.Stop()
		tick = t.C
	}

	flush := func() {
		if len(batch) == 0 {
			return
		}
		s.persist(batch)
		batch = batch[:0]
	}

	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				flush()
				return
			}
			s.logEvent(ev)
			if s.opts.Sink != nil {
				batch = append(batch, ev)
				if len(batch) >= s.opts.BatchSize {
					flush()
				}
			}
		case <-tick:
			flush()
		}
	}
}

// logEvent writes the event to zap. Decision: zap stays the always-on sink so
// a persistence failure never loses the record.
func (s *Service) logEvent(ev Event) {
	fields := []zap.Field{
		zap.String("audit_event", ev.Type),
		zap.String("actor_id", ev.ActorID),
		zap.String("target_id", ev.TargetID),
		zap.Time("event_time", ev.Timestamp),
	}
	if ev.IP != "" {
		fields = append(fields, zap.String("ip", ev.IP))
	}
	for k, v := range ev.Metadata {
		fields = append(fields, zap.String("meta_"+k, v))
	}
	s.logger.Info("audit", fields...)
}

// persist inserts the batch; on failure it logs, counts the events as dropped
// and relies on the zap records already written.
func (s *Service) persist(batch []Event) {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	if err := s.opts.Sink.InsertBatch(ctx, batch); err != nil {
		s.logger.Error("audit persist failed, events kept in log only",
			zap.Int("events", len(batch)),
			zap.Error(err),
		)
		s.recordDropped(DropReasonSinkError, len(batch))
	}
}

// retentionLoop purges expired rows once at start-up and then daily until Close.
func (s *Service) retentionLoop() {
	defer s.retentionWG.Done()
	s.purge()
	t := time.NewTicker(retentionInterval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			s.purge()
		case <-s.stop:
			return
		}
	}
}

func (s *Service) purge() {
	ctx, cancel := context.WithTimeout(context.Background(), flushTimeout)
	defer cancel()
	cutoff := s.now().UTC().AddDate(0, 0, -s.opts.RetentionDays)
	n, err := s.opts.Sink.DeleteOlderThan(ctx, cutoff)
	if err != nil {
		s.logger.Error("audit retention purge failed", zap.Time("cutoff", cutoff), zap.Error(err))
		return
	}
	s.logger.Info("audit retention purge", zap.Time("cutoff", cutoff), zap.Int64("deleted", n))
}
