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
	EventPasswordExpired    = "password_expired"
	EventHashUpgraded       = "hash_upgraded"
	EventPasswordReused     = "password_reused"
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
	EventAdminAPIKeyCreate  = "admin_apikey_create"
	EventAdminAPIKeyUpdate  = "admin_apikey_update"
	EventAdminAPIKeyRevoke  = "admin_apikey_revoke"
	EventAdminAPIKeyRotate  = "admin_apikey_rotate"
	EventAdminWebhookCreate = "admin_webhook_create"
	EventAdminWebhookUpdate = "admin_webhook_update"
	EventAdminWebhookDelete = "admin_webhook_delete"
	EventAdminWebhookTest   = "admin_webhook_test"
	EventAdminWebhookRetry  = "admin_webhook_retry"
	EventMFAMaxAttempts     = "mfa_max_attempts"
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

// Repository is an optional persistence backend for audit events.
// When set on Service, events are written to the database in addition to zap.
type Repository interface {
	Insert(ctx context.Context, entry *RepositoryEntry) error
}

// RepositoryEntry is the data shape expected by the persistence layer.
type RepositoryEntry struct {
	EventType string
	ActorID   string
	TargetID  string
	IP        string
	Severity  string
	Metadata  map[string]string
	CreatedAt time.Time
}

// Service implements EventLogger with an async buffered channel. Events are
// drained on Close so nothing is lost during graceful shutdown.
type Service struct {
	logger *zap.Logger
	repo   Repository
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

// SetRepository attaches a persistence backend. Must be called before events
// are emitted (typically during bootstrap, before traffic starts).
func (s *Service) SetRepository(repo Repository) {
	s.repo = repo
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

// severityForEvent returns a severity level based on the event type.
func severityForEvent(eventType string) string {
	switch eventType {
	case EventLoginFailure, EventPasswordReused, EventMFAMaxAttempts:
		return "warning"
	case EventAdminUserLock, EventAdminUserDelete, EventAdminClientDelete,
		EventAdminAPIKeyRevoke, EventAdminWebhookDelete:
		return "high"
	default:
		return "info"
	}
}

// drain reads events from the channel, logs them via zap, and optionally
// persists them to the audit_logs table via the repository.
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

		if s.repo != nil {
			entry := &RepositoryEntry{
				EventType: ev.Type,
				ActorID:   ev.ActorID,
				TargetID:  ev.TargetID,
				IP:        ev.IP,
				Severity:  severityForEvent(ev.Type),
				Metadata:  ev.Metadata,
				CreatedAt: ev.Timestamp,
			}
			if err := s.repo.Insert(context.Background(), entry); err != nil {
				s.logger.Warn("audit persist failed",
					zap.String("event_type", ev.Type),
					zap.Error(err),
				)
			}
		}
	}
}

// NopLogger is a no-op implementation of EventLogger for use in tests.
type NopLogger struct{}

// LogEvent does nothing.
func (NopLogger) LogEvent(_ context.Context, _ Event) {}
