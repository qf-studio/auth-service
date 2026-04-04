package audit

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	event := NewEvent(EventLoginSuccess, OutcomeSuccess)

	require.NotNil(t, event)
	assert.NotEmpty(t, event.ID)
	assert.Equal(t, EventLoginSuccess, event.EventType)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.False(t, event.Timestamp.IsZero())
	assert.WithinDuration(t, time.Now().UTC(), event.Timestamp, time.Second)
	assert.NotNil(t, event.Metadata)
}

func TestNewEvent_UniqueIDs(t *testing.T) {
	e1 := NewEvent(EventLoginSuccess, OutcomeSuccess)
	e2 := NewEvent(EventLoginSuccess, OutcomeSuccess)
	assert.NotEqual(t, e1.ID, e2.ID)
}

func TestAuditEvent_BuilderChain(t *testing.T) {
	event := NewEvent(EventUserCreate, OutcomeSuccess).
		WithSubject("user-123", "user").
		WithResource("user", "user-456").
		WithRequest("192.168.1.1", "Mozilla/5.0", "req-abc").
		WithComponent("auth").
		WithAction("created user account").
		WithMeta("email", "test@example.com")

	assert.Equal(t, EventUserCreate, event.EventType)
	assert.Equal(t, OutcomeSuccess, event.Outcome)
	assert.Equal(t, "user-123", event.SubjectID)
	assert.Equal(t, "user", event.SubjectType)
	assert.Equal(t, "user", event.ResourceType)
	assert.Equal(t, "user-456", event.ResourceID)
	assert.Equal(t, "192.168.1.1", event.SourceIP)
	assert.Equal(t, "Mozilla/5.0", event.UserAgent)
	assert.Equal(t, "req-abc", event.CorrelationID)
	assert.Equal(t, "auth", event.Component)
	assert.Equal(t, "created user account", event.Action)
	assert.Equal(t, "test@example.com", event.Metadata["email"])
}

func TestAuditEvent_WithMeta_Multiple(t *testing.T) {
	event := NewEvent(EventLoginFailure, OutcomeFailure).
		WithMeta("reason", "invalid_password").
		WithMeta("attempt", "3")

	assert.Equal(t, "invalid_password", event.Metadata["reason"])
	assert.Equal(t, "3", event.Metadata["attempt"])
	assert.Len(t, event.Metadata, 2)
}

func TestOutcomeConstants(t *testing.T) {
	assert.Equal(t, Outcome("success"), OutcomeSuccess)
	assert.Equal(t, Outcome("failure"), OutcomeFailure)
	assert.Equal(t, Outcome("denied"), OutcomeDenied)
}

func TestEventTypeConstants(t *testing.T) {
	// Verify key event types are non-empty and distinct.
	types := []EventType{
		EventLoginSuccess, EventLoginFailure, EventLogout,
		EventTokenRefresh, EventTokenRevoke, EventTokenIntrospect,
		EventClientCredentials,
		EventUserCreate, EventUserUpdate, EventUserDelete,
		EventUserLock, EventUserUnlock,
		EventPasswordChange, EventPasswordReset, EventPasswordResetRequest,
		EventClientCreate, EventClientUpdate, EventClientDelete, EventClientSecretRotate,
		EventMFAEnroll, EventMFAVerify, EventMFADisenroll,
		EventSessionCreate, EventSessionTerminate,
		EventAdminAction, EventRateLimitTriggered,
	}

	seen := make(map[EventType]bool, len(types))
	for _, et := range types {
		assert.NotEmpty(t, string(et), "event type must not be empty")
		assert.False(t, seen[et], "duplicate event type: %s", et)
		seen[et] = true
	}
}
