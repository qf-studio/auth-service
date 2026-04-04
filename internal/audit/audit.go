// Package audit provides structured audit event logging for security-relevant
// operations. Events are dispatched asynchronously via a buffered channel and
// persisted by a pluggable repository.
package audit

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// Event types for all auditable operations.
const (
	EventLoginSuccess       = "login_success"
	EventLoginFailure       = "login_failure"
	EventRegister           = "register"
	EventLogout             = "logout"
	EventLogoutAll          = "logout_all"
	EventPasswordChange     = "password_change"
	EventPasswordReset      = "password_reset"
	EventPasswordResetConfm = "password_reset_confirm"
	EventTokenRefresh       = "token_refresh"
	EventTokenRevoke        = "token_revoke"
	EventAdminUserCreate    = "admin_user_create"
	EventAdminUserUpdate    = "admin_user_update"
	EventAdminUserDelete    = "admin_user_delete"
	EventAdminUserLock      = "admin_user_lock"
	EventAdminUserUnlock    = "admin_user_unlock"
	EventAdminClientCreate  = "admin_client_create"
	EventAdminClientUpdate  = "admin_client_update"
	EventAdminClientDelete  = "admin_client_delete"
	EventAdminClientRotate  = "admin_client_rotate_secret"
	EventTokenIntrospect    = "token_introspect"
)

// Event represents a single audit log entry.
type Event struct {
	Type      string
	ActorID   string // user or client performing the action
	TargetID  string // resource being acted upon
	IP        string
	Metadata  map[string]string
	Timestamp time.Time
}

// EventLogger is the interface consumed by services to emit audit events.
type EventLogger interface {
	LogEvent(ctx context.Context, event Event)
}

// Service implements EventLogger with an async buffered channel. Events are
// drained on Close so nothing is lost during graceful shutdown.
type Service struct {
	logger *zap.Logger
	ch     chan Event
	done   chan struct{}
}

// NewService creates an audit Service with the given buffer size.
// Events exceeding the buffer are logged and dropped (non-blocking).
func NewService(logger *zap.Logger, bufferSize int) *Service {
	if bufferSize <= 0 {
		bufferSize = 1024
	}
	s := &Service{
		logger: logger,
		ch:     make(chan Event, bufferSize),
		done:   make(chan struct{}),
	}
	go s.drain()
	return s
}

// LogEvent enqueues an audit event. It is non-blocking; if the buffer is full
// the event is logged at warn level and dropped.
func (s *Service) LogEvent(_ context.Context, event Event) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	select {
	case s.ch <- event:
	default:
		s.logger.Warn("audit buffer full, event dropped",
			zap.String("event_type", event.Type),
			zap.String("actor_id", event.ActorID),
		)
	}
}

// Close signals the drain goroutine to flush remaining events and waits for
// completion. Implements httpserver.Closer semantics.
func (s *Service) Close() error {
	close(s.ch)
	<-s.done
	return nil
}

// Name returns the closer label for shutdown logging.
func (s *Service) Name() string { return "audit" }

// drain reads events from the channel and logs them via zap structured fields.
// In a future iteration this will persist to the audit_log table via a repository.
func (s *Service) drain() {
	defer close(s.done)
	for ev := range s.ch {
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
}

// NopLogger is a no-op implementation of EventLogger for use in tests.
type NopLogger struct{}

// LogEvent does nothing.
func (NopLogger) LogEvent(_ context.Context, _ Event) {}
