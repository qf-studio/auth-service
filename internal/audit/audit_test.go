package audit

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func TestService_LogEvent_DrainOnClose(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	svc := NewService(logger, 64)

	svc.LogEvent(context.Background(), Event{
		Type:     EventLoginSuccess,
		ActorID:  "user-1",
		TargetID: "user-1",
	})
	svc.LogEvent(context.Background(), Event{
		Type:     EventLogout,
		ActorID:  "user-2",
		TargetID: "user-2",
	})

	err := svc.Close()
	require.NoError(t, err)

	assert.Equal(t, 2, logs.Len(), "expected 2 audit log entries after drain")

	entry := logs.All()[0]
	assert.Equal(t, "audit", entry.Message)

	fields := make(map[string]string)
	for _, f := range entry.ContextMap() {
		if s, ok := f.(string); ok {
			fields[entry.ContextMap()["audit_event"].(string)] = s
		}
	}
	assert.Equal(t, EventLoginSuccess, entry.ContextMap()["audit_event"])
	assert.Equal(t, "user-1", entry.ContextMap()["actor_id"])
}

func TestService_LogEvent_SetsTimestamp(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	svc := NewService(logger, 64)

	before := time.Now().UTC()
	svc.LogEvent(context.Background(), Event{
		Type:    EventRegister,
		ActorID: "user-3",
	})
	err := svc.Close()
	require.NoError(t, err)

	require.Equal(t, 1, logs.Len())
	eventTime := logs.All()[0].ContextMap()["event_time"].(time.Time)
	assert.False(t, eventTime.Before(before), "event timestamp should be >= before")
}

func TestService_LogEvent_BufferFull_Drops(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	// Buffer size 1, fill the channel by blocking the drain goroutine.
	svc := &Service{
		logger: logger,
		ch:     make(chan Event, 1),
		done:   make(chan struct{}),
	}

	// Fill the buffer without draining.
	svc.ch <- Event{Type: EventLoginSuccess}

	// This one should be dropped and produce a warning.
	svc.LogEvent(context.Background(), Event{Type: EventLogout})

	assert.Equal(t, 1, logs.Len(), "expected 1 warn log for dropped event")
	assert.Equal(t, "audit buffer full, event dropped", logs.All()[0].Message)

	// Drain to avoid goroutine leak.
	<-svc.ch
	close(svc.ch)
	close(svc.done)
}

func TestService_Name(t *testing.T) {
	svc := NewService(zap.NewNop(), 1)
	assert.Equal(t, "audit", svc.Name())
	_ = svc.Close()
}

func TestService_PersistsToRepository(t *testing.T) {
	core, _ := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	var persisted []*RepositoryEntry
	repo := &mockRepo{
		insertFn: func(_ context.Context, entry *RepositoryEntry) error {
			persisted = append(persisted, entry)
			return nil
		},
	}

	svc := NewService(logger, 64)
	svc.SetRepository(repo)

	svc.LogEvent(context.Background(), Event{
		Type:     EventLoginFailure,
		ActorID:  "user-1",
		TargetID: "user-1",
		IP:       "10.0.0.1",
	})

	err := svc.Close()
	require.NoError(t, err)

	require.Len(t, persisted, 1)
	assert.Equal(t, EventLoginFailure, persisted[0].EventType)
	assert.Equal(t, "user-1", persisted[0].ActorID)
	assert.Equal(t, "warning", persisted[0].Severity)
	assert.Equal(t, "10.0.0.1", persisted[0].IP)
}

func TestService_PersistError_DoesNotBlock(t *testing.T) {
	core, logs := observer.New(zap.WarnLevel)
	logger := zap.New(core)

	repo := &mockRepo{
		insertFn: func(_ context.Context, _ *RepositoryEntry) error {
			return assert.AnError
		},
	}

	svc := NewService(logger, 64)
	svc.SetRepository(repo)

	svc.LogEvent(context.Background(), Event{
		Type:    EventLoginSuccess,
		ActorID: "user-1",
	})

	err := svc.Close()
	require.NoError(t, err)

	// Should have logged a warning about persist failure.
	require.Equal(t, 1, logs.Len())
	assert.Equal(t, "audit persist failed", logs.All()[0].Message)
}

func TestSeverityForEvent(t *testing.T) {
	tests := []struct {
		event    string
		expected string
	}{
		{EventLoginFailure, "warning"},
		{EventPasswordReused, "warning"},
		{EventMFAMaxAttempts, "warning"},
		{EventAdminUserLock, "high"},
		{EventAdminUserDelete, "high"},
		{EventLoginSuccess, "info"},
		{EventRegister, "info"},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, severityForEvent(tt.event), "event: %s", tt.event)
	}
}

// mockRepo implements audit.Repository for tests.
type mockRepo struct {
	insertFn func(ctx context.Context, entry *RepositoryEntry) error
}

func (m *mockRepo) Insert(ctx context.Context, entry *RepositoryEntry) error {
	if m.insertFn != nil {
		return m.insertFn(ctx, entry)
	}
	return nil
}

func TestNopLogger_DoesNotPanic(t *testing.T) {
	nop := NopLogger{}
	nop.LogEvent(context.Background(), Event{
		Type:    EventLoginSuccess,
		ActorID: "test",
	})
}
