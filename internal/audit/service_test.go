package audit

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"

	"github.com/qf-studio/auth-service/internal/domain"
)

type fakeSink struct {
	mu       sync.Mutex
	batches  [][]Event
	err      error
	deletes  []time.Time
	deleted  int64
	entered  chan struct{} // receives once per InsertBatch call when non-nil
	release  chan struct{} // InsertBatch blocks until it is closed when non-nil
	purgedCh chan struct{}
}

func (f *fakeSink) InsertBatch(_ context.Context, events []Event) error {
	if f.entered != nil {
		f.entered <- struct{}{}
	}
	if f.release != nil {
		<-f.release
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return f.err
	}
	f.batches = append(f.batches, append([]Event(nil), events...))
	return nil
}

func (f *fakeSink) DeleteOlderThan(_ context.Context, cutoff time.Time) (int64, error) {
	f.mu.Lock()
	f.deletes = append(f.deletes, cutoff)
	n := f.deleted
	f.mu.Unlock()
	if f.purgedCh != nil {
		f.purgedCh <- struct{}{}
	}
	return n, nil
}

func (f *fakeSink) allEvents() []Event {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Event
	for _, b := range f.batches {
		out = append(out, b...)
	}
	return out
}

type fakeDrops struct {
	mu     sync.Mutex
	counts map[string]int
}

func (d *fakeDrops) RecordAuditDropped(reason string, n int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.counts == nil {
		d.counts = map[string]int{}
	}
	d.counts[reason] += n
}

func (d *fakeDrops) get(reason string) int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.counts[reason]
}

func TestService_PersistsEventsOnClose(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	sink := &fakeSink{}
	svc := NewServiceWithOptions(zap.New(core), 16, Options{Sink: sink, FlushInterval: time.Hour})

	tenant := uuid.New()
	ctx := domain.WithTenantID(context.Background(), tenant)
	svc.LogEvent(ctx, Event{Type: EventLoginSuccess, ActorID: "u1", TargetID: "u1", IP: "10.0.0.1", UserAgent: "ua", Metadata: map[string]string{"k": "v"}})
	svc.LogEvent(ctx, Event{Type: EventLogout, ActorID: "u1", TargetID: "u1"})
	svc.LogEvent(context.Background(), Event{Type: EventRegister, ActorID: "u2", TargetID: "u2", TenantID: tenant})

	require.NoError(t, svc.Close())

	got := sink.allEvents()
	require.Len(t, got, 3)
	assert.Equal(t, tenant, got[0].TenantID, "tenant resolved from context")
	assert.Equal(t, "ua", got[0].UserAgent)
	assert.Equal(t, "10.0.0.1", got[0].IP)
	assert.Equal(t, map[string]string{"k": "v"}, got[0].Metadata)
	assert.False(t, got[0].Timestamp.IsZero())
	assert.Equal(t, tenant, got[2].TenantID, "explicit tenant kept")
	assert.Equal(t, 3, logs.Len(), "zap keeps every record")
}

func TestService_TenantDefaultsWhenContextHasNone(t *testing.T) {
	sink := &fakeSink{}
	svc := NewServiceWithOptions(zap.NewNop(), 4, Options{Sink: sink})
	svc.LogEvent(context.Background(), Event{Type: EventLogout})
	require.NoError(t, svc.Close())

	got := sink.allEvents()
	require.Len(t, got, 1)
	assert.Equal(t, domain.DefaultTenantID, got[0].TenantID)
}

func TestService_FlushesFullBatchesAndOnInterval(t *testing.T) {
	sink := &fakeSink{}
	svc := NewServiceWithOptions(zap.NewNop(), 16, Options{Sink: sink, BatchSize: 2, FlushInterval: 20 * time.Millisecond})

	for i := 0; i < 3; i++ {
		svc.LogEvent(context.Background(), Event{Type: EventLogout})
	}
	// 2 flushed by size, the third by the interval — all before Close.
	require.Eventually(t, func() bool { return len(sink.allEvents()) == 3 }, 2*time.Second, 5*time.Millisecond)

	sink.mu.Lock()
	assert.Equal(t, 2, len(sink.batches[0]), "first batch is full-size")
	sink.mu.Unlock()
	require.NoError(t, svc.Close())
}

func TestService_SinkErrorKeepsZapRecordAndCounts(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	drops := &fakeDrops{}
	sink := &fakeSink{err: errors.New("db down")}
	svc := NewServiceWithOptions(zap.New(core), 16, Options{Sink: sink, Drops: drops, FlushInterval: time.Hour})

	svc.LogEvent(context.Background(), Event{Type: EventLogout})
	svc.LogEvent(context.Background(), Event{Type: EventLoginSuccess})
	require.NoError(t, svc.Close())

	assert.Equal(t, 2, drops.get(DropReasonSinkError))
	assert.Equal(t, 2, logs.FilterMessage("audit").Len(), "zap record kept on DB error")
	assert.Equal(t, 1, logs.FilterMessage("audit persist failed, events kept in log only").Len())
}

func TestService_BufferFullIncrementsDroppedMetric(t *testing.T) {
	sink := &fakeSink{entered: make(chan struct{}, 4), release: make(chan struct{})}
	drops := &fakeDrops{}
	svc := NewServiceWithOptions(zap.NewNop(), 1, Options{Sink: sink, Drops: drops, BatchSize: 1})

	ctx := context.Background()
	svc.LogEvent(ctx, Event{Type: EventLogout}) // taken by drain, which blocks in the sink
	<-sink.entered
	svc.LogEvent(ctx, Event{Type: EventLogout}) // fills the 1-slot buffer
	svc.LogEvent(ctx, Event{Type: EventLogout}) // dropped
	svc.LogEvent(ctx, Event{Type: EventLogout}) // dropped

	assert.Equal(t, 2, drops.get(DropReasonBufferFull))

	close(sink.release)
	require.NoError(t, svc.Close())
	assert.Len(t, sink.allEvents(), 2, "only the accepted events are persisted")
	assert.Equal(t, 0, drops.get(DropReasonSinkError))
}

func TestService_ZapOnlyWithoutSink(t *testing.T) {
	core, logs := observer.New(zap.InfoLevel)
	svc := NewService(zap.New(core), 4)
	svc.LogEvent(context.Background(), Event{Type: EventLogout})
	require.NoError(t, svc.Close())
	assert.Equal(t, 1, logs.Len())
}

func TestService_RetentionPurgesOnStartAndOnClose(t *testing.T) {
	sink := &fakeSink{purgedCh: make(chan struct{}, 4), deleted: 7}
	fixed := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)

	core, logs := observer.New(zap.InfoLevel)
	svc := &Service{
		logger: zap.New(core),
		ch:     make(chan Event, 1),
		done:   make(chan struct{}),
		opts:   Options{Sink: sink, RetentionDays: 30, BatchSize: 1, FlushInterval: time.Hour},
		stop:   make(chan struct{}),
		now:    func() time.Time { return fixed },
	}
	go svc.drain()
	svc.retentionWG.Add(1)
	go svc.retentionLoop()

	<-sink.purgedCh
	require.NoError(t, svc.Close())

	sink.mu.Lock()
	defer sink.mu.Unlock()
	require.Len(t, sink.deletes, 1)
	assert.Equal(t, fixed.AddDate(0, 0, -30), sink.deletes[0])
	assert.Equal(t, 1, logs.FilterMessage("audit retention purge").Len())
}

func TestService_RetentionDisabledWhenZero(t *testing.T) {
	sink := &fakeSink{}
	svc := NewServiceWithOptions(zap.NewNop(), 4, Options{Sink: sink, RetentionDays: 0})
	require.NoError(t, svc.Close())
	sink.mu.Lock()
	defer sink.mu.Unlock()
	assert.Empty(t, sink.deletes)
}
