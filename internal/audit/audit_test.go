package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/qf-studio/auth-service/internal/domain"
)

func TestService_LogEvent_DrainOnClose(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	svc := NewService(logger, 64, nil)

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

	svc := NewService(logger, 64, nil)

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
	svc := NewService(zap.NewNop(), 1, nil)
	assert.Equal(t, "audit", svc.Name())
	_ = svc.Close()
}

func TestNopLogger_DoesNotPanic(t *testing.T) {
	nop := NopLogger{}
	nop.LogEvent(context.Background(), Event{
		Type:    EventLoginSuccess,
		ActorID: "test",
	})
}

// mockRepo implements Repository for unit testing.
type mockRepo struct {
	mu      sync.Mutex
	entries []*domain.AuditLog
	err     error // if set, Create returns this error
}

func (m *mockRepo) Create(_ context.Context, entry *domain.AuditLog) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.entries = append(m.entries, entry)
	return nil
}

func (m *mockRepo) allEntries() []*domain.AuditLog {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*domain.AuditLog, len(m.entries))
	copy(out, m.entries)
	return out
}

func TestService_PersistsEvents(t *testing.T) {
	repo := &mockRepo{}
	svc := NewService(zap.NewNop(), 64, repo)

	svc.LogEvent(context.Background(), Event{
		Type:     EventLoginSuccess,
		ActorID:  "user-1",
		TargetID: "session-1",
		IP:       "10.0.0.1",
		Metadata: map[string]string{"browser": "chrome"},
	})
	svc.LogEvent(context.Background(), Event{
		Type:     EventLogout,
		ActorID:  "user-2",
		TargetID: "session-2",
	})

	require.NoError(t, svc.Close())

	entries := repo.allEntries()
	require.Len(t, entries, 2)

	assert.Equal(t, EventLoginSuccess, entries[0].EventType)
	assert.Equal(t, "user-1", entries[0].ActorID)
	assert.Equal(t, "session-1", entries[0].TargetID)
	assert.Equal(t, "10.0.0.1", entries[0].IP)
	assert.Equal(t, "chrome", entries[0].Metadata["browser"])

	assert.Equal(t, EventLogout, entries[1].EventType)
	assert.Equal(t, "user-2", entries[1].ActorID)
}

func TestService_PersistError_StillLogs(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	repo := &mockRepo{err: errors.New("db down")}
	svc := NewService(logger, 64, repo)

	svc.LogEvent(context.Background(), Event{
		Type:    EventRegister,
		ActorID: "user-5",
	})
	require.NoError(t, svc.Close())

	// Event should still be logged even though persistence failed.
	var foundAudit, foundError bool
	for _, entry := range logs.All() {
		switch entry.Message {
		case "audit":
			foundAudit = true
		case "audit persist failed":
			foundError = true
		}
	}
	assert.True(t, foundAudit, "expected audit log entry")
	assert.True(t, foundError, "expected error log for failed persistence")
}

func TestService_NilRepo_NoError(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	logger := zap.New(core)

	svc := NewService(logger, 64, nil)

	svc.LogEvent(context.Background(), Event{
		Type:    EventLoginSuccess,
		ActorID: "user-10",
	})
	require.NoError(t, svc.Close())

	// Should log without errors (no persist error since repo is nil).
	assert.Equal(t, 1, logs.Len())
	assert.Equal(t, "audit", logs.All()[0].Message)
}
