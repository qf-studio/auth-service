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

func TestNopLogger_DoesNotPanic(t *testing.T) {
	nop := NopLogger{}
	nop.LogEvent(context.Background(), Event{
		Type:    EventLoginSuccess,
		ActorID: "test",
	})
}
