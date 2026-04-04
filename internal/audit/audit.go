// Package audit provides structured audit logging for the auth service.
// Events are captured asynchronously via a buffered channel and persisted
// to PostgreSQL through the storage layer.
package audit

import (
	"time"

	"github.com/google/uuid"
)

// Outcome represents the result of an auditable action.
type Outcome string

const (
	OutcomeSuccess Outcome = "success"
	OutcomeFailure Outcome = "failure"
	OutcomeDenied  Outcome = "denied"
)

// EventType constants follow NIST SP 800-53 AU-2/AU-3 categories.
type EventType string

const (
	// Authentication events.
	EventLoginSuccess       EventType = "auth.login.success"
	EventLoginFailure       EventType = "auth.login.failure"
	EventLogout             EventType = "auth.logout"
	EventTokenRefresh       EventType = "auth.token.refresh"
	EventTokenRevoke        EventType = "auth.token.revoke"
	EventTokenIntrospect    EventType = "auth.token.introspect"
	EventClientCredentials  EventType = "auth.client_credentials"

	// User lifecycle events.
	EventUserCreate         EventType = "user.create"
	EventUserUpdate         EventType = "user.update"
	EventUserDelete         EventType = "user.delete"
	EventUserLock           EventType = "user.lock"
	EventUserUnlock         EventType = "user.unlock"
	EventPasswordChange     EventType = "user.password.change"
	EventPasswordReset      EventType = "user.password.reset"
	EventPasswordResetRequest EventType = "user.password.reset_request"

	// Client lifecycle events.
	EventClientCreate       EventType = "client.create"
	EventClientUpdate       EventType = "client.update"
	EventClientDelete       EventType = "client.delete"
	EventClientSecretRotate EventType = "client.secret.rotate"

	// MFA events (Phase 2).
	EventMFAEnroll          EventType = "mfa.enroll"
	EventMFAVerify          EventType = "mfa.verify"
	EventMFADisenroll       EventType = "mfa.disenroll"

	// Session events.
	EventSessionCreate      EventType = "session.create"
	EventSessionTerminate   EventType = "session.terminate"

	// Admin / privilege events.
	EventAdminAction        EventType = "admin.action"
	EventRateLimitTriggered EventType = "security.rate_limit"
)

// AuditEvent represents a single auditable action in the system.
// All fields follow NIST SP 800-53 AU-3 requirements.
type AuditEvent struct {
	// ID is the unique identifier for this event (UUID v4).
	ID string

	// EventType categorises the action (e.g. "auth.login.success").
	EventType EventType

	// Outcome indicates whether the action succeeded, failed, or was denied.
	Outcome Outcome

	// Timestamp is the UTC time the event occurred.
	Timestamp time.Time

	// SubjectID is the user or client that performed the action.
	// Empty for unauthenticated attempts.
	SubjectID string

	// SubjectType describes the actor: "user", "client", or "system".
	SubjectType string

	// ResourceType is the kind of resource affected (e.g. "user", "token").
	ResourceType string

	// ResourceID identifies the specific resource affected.
	ResourceID string

	// Action is a human-readable description of the operation.
	Action string

	// SourceIP is the IP address of the request originator.
	SourceIP string

	// UserAgent is the HTTP User-Agent header value.
	UserAgent string

	// CorrelationID links this event to a request trace.
	CorrelationID string

	// Component identifies the service module that emitted the event.
	Component string

	// Metadata holds additional key-value pairs for context.
	// Never store passwords, secrets, or full tokens here.
	Metadata map[string]string
}

// NewEvent creates a new AuditEvent with a generated ID and UTC timestamp.
func NewEvent(eventType EventType, outcome Outcome) *AuditEvent {
	return &AuditEvent{
		ID:        uuid.New().String(),
		EventType: eventType,
		Outcome:   outcome,
		Timestamp: time.Now().UTC(),
		Metadata:  make(map[string]string),
	}
}

// WithSubject sets the subject (actor) fields.
func (e *AuditEvent) WithSubject(id, subjectType string) *AuditEvent {
	e.SubjectID = id
	e.SubjectType = subjectType
	return e
}

// WithResource sets the resource fields.
func (e *AuditEvent) WithResource(resourceType, resourceID string) *AuditEvent {
	e.ResourceType = resourceType
	e.ResourceID = resourceID
	return e
}

// WithRequest sets HTTP request context fields.
func (e *AuditEvent) WithRequest(sourceIP, userAgent, correlationID string) *AuditEvent {
	e.SourceIP = sourceIP
	e.UserAgent = userAgent
	e.CorrelationID = correlationID
	return e
}

// WithComponent sets the emitting component.
func (e *AuditEvent) WithComponent(component string) *AuditEvent {
	e.Component = component
	return e
}

// WithAction sets the human-readable action description.
func (e *AuditEvent) WithAction(action string) *AuditEvent {
	e.Action = action
	return e
}

// WithMeta adds a key-value pair to the event metadata.
func (e *AuditEvent) WithMeta(key, value string) *AuditEvent {
	e.Metadata[key] = value
	return e
}
