package audit

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"
)

// mockRepo is a test double for the audit Repository.
type mockRepo struct {
	mu     sync.Mutex
	events []*AuditEvent
	err    error
	calls  atomic.Int64
}

func (m *mockRepo) Insert(_ context.Context, event *AuditEvent) error {
	m.calls.Add(1)
	if m.err != nil {
		return m.err
	}
	m.mu.Lock()
	m.events = append(m.events, event)
	m.mu.Unlock()
	return nil
}

func (m *mockRepo) getEvents() []*AuditEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*AuditEvent, len(m.events))
	copy(cp, m.events)
	return cp
}

func newTestService(t *testing.T, repo *mockRepo, bufSize int) *Service {
	t.Helper()
	logger := zaptest.NewLogger(t)
	return NewService(repo, logger, bufSize)
}

func TestService_LogEvent_Success(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	event := NewEvent(EventLoginSuccess, OutcomeSuccess).
		WithSubject("user-1", "user")

	err := svc.LogEvent(event)
	require.NoError(t, err)

	// Give the worker time to process.
	assert.Eventually(t, func() bool {
		return repo.calls.Load() == 1
	}, time.Second, 10*time.Millisecond)

	events := repo.getEvents()
	require.Len(t, events, 1)
	assert.Equal(t, event.ID, events[0].ID)
}

func TestService_LogEvent_MultipleEvents(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 100)
	defer svc.Close()

	const count = 50
	for i := 0; i < count; i++ {
		err := svc.LogEvent(NewEvent(EventLoginSuccess, OutcomeSuccess))
		require.NoError(t, err)
	}

	assert.Eventually(t, func() bool {
		return repo.calls.Load() == int64(count)
	}, 2*time.Second, 10*time.Millisecond)

	events := repo.getEvents()
	assert.Len(t, events, count)
}

func TestService_Close_FlushesRemaining(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 100)

	const count = 20
	for i := 0; i < count; i++ {
		err := svc.LogEvent(NewEvent(EventUserCreate, OutcomeSuccess))
		require.NoError(t, err)
	}

	svc.Close()

	// After Close, all events must be flushed.
	events := repo.getEvents()
	assert.Len(t, events, count)
}

func TestService_Close_Idempotent(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)

	svc.Close()
	svc.Close() // Must not panic.
}

func TestService_LogEvent_AfterClose(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	svc.Close()

	err := svc.LogEvent(NewEvent(EventLoginSuccess, OutcomeSuccess))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "service closed")
}

func TestService_LogEvent_NilEvent(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	err := svc.LogEvent(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "must not be nil")
}

func TestService_LogEvent_MissingID(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	event := &AuditEvent{
		EventType: EventLoginSuccess,
		Outcome:   OutcomeSuccess,
		Timestamp: time.Now().UTC(),
	}
	err := svc.LogEvent(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event ID is required")
}

func TestService_LogEvent_MissingEventType(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	event := &AuditEvent{
		ID:        "test-id",
		Outcome:   OutcomeSuccess,
		Timestamp: time.Now().UTC(),
	}
	err := svc.LogEvent(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "event type is required")
}

func TestService_LogEvent_MissingOutcome(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	event := &AuditEvent{
		ID:        "test-id",
		EventType: EventLoginSuccess,
		Timestamp: time.Now().UTC(),
	}
	err := svc.LogEvent(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "outcome is required")
}

func TestService_LogEvent_MissingTimestamp(t *testing.T) {
	repo := &mockRepo{}
	svc := newTestService(t, repo, 10)
	defer svc.Close()

	event := &AuditEvent{
		ID:        "test-id",
		EventType: EventLoginSuccess,
		Outcome:   OutcomeSuccess,
	}
	err := svc.LogEvent(event)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "timestamp is required")
}

func TestService_RepoError_LoggedNotPropagated(t *testing.T) {
	repo := &mockRepo{err: errors.New("db connection failed")}
	svc := newTestService(t, repo, 10)

	err := svc.LogEvent(NewEvent(EventLoginSuccess, OutcomeSuccess))
	require.NoError(t, err) // Error is async, not returned to caller.

	// Wait for the worker to attempt persistence.
	assert.Eventually(t, func() bool {
		return repo.calls.Load() == 1
	}, time.Second, 10*time.Millisecond)

	// No events stored because repo returned error.
	events := repo.getEvents()
	assert.Empty(t, events)

	svc.Close()
}

func TestService_DefaultBufferSize(t *testing.T) {
	repo := &mockRepo{}
	logger := zap.NewNop()
	svc := NewService(repo, logger, 0)
	defer svc.Close()

	assert.Equal(t, DefaultBufferSize, cap(svc.eventCh))
}

func TestService_NegativeBufferSize_UsesDefault(t *testing.T) {
	repo := &mockRepo{}
	logger := zap.NewNop()
	svc := NewService(repo, logger, -5)
	defer svc.Close()

	assert.Equal(t, DefaultBufferSize, cap(svc.eventCh))
}
