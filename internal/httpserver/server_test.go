package httpserver_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest"

	"github.com/qf-studio/auth-service/internal/httpserver"
)

func init() {
	gin.SetMode(gin.TestMode)
}

// healthHandler returns 200 {"status":"ok"}.
func healthHandler() http.Handler {
	r := gin.New()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	return r
}

// slowHandler blocks for 100 ms to simulate an in-flight request.
func slowHandler() http.Handler {
	r := gin.New()
	r.GET("/slow", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond)
		c.JSON(http.StatusOK, gin.H{"status": "done"})
	})
	return r
}

// mockCloser records whether Close was called.
type mockCloser struct {
	name   string
	closed atomic.Bool
	err    error
}

func (m *mockCloser) Name() string { return m.name }
func (m *mockCloser) Close() error {
	m.closed.Store(true)
	return m.err
}

// startServer is a test helper: creates and starts a Server, returns it and the bound address.
func startServer(t *testing.T, logger *zap.Logger, handler http.Handler, closers []httpserver.Closer) (srv *httpserver.Server, addr string) {
	t.Helper()
	httpSrv := &http.Server{
		Addr:              ":0", // random port
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	s := httpserver.New(logger, []*http.Server{httpSrv}, closers)
	listeners, err := s.Start()
	require.NoError(t, err)
	addr = listeners[0].Addr().String()
	return s, addr
}

// TestServer_HealthEndpointReachable verifies that the health probe responds 200 after start.
func TestServer_HealthEndpointReachable(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s, addr := startServer(t, logger, healthHandler(), nil)
	defer s.Shutdown(context.Background())

	resp, err := http.Get(fmt.Sprintf("http://%s/health", addr))
	require.NoError(t, err)
	defer func() { _ = resp.Body.Close() }()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	assert.Contains(t, string(body), `"ok"`)
}

// TestServer_GracefulShutdown verifies that after Shutdown the server stops accepting connections.
func TestServer_GracefulShutdown(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s, addr := startServer(t, logger, healthHandler(), nil)

	// Confirm server is reachable before shutdown.
	resp, err := http.Get(fmt.Sprintf("http://%s/health", addr))
	require.NoError(t, err)
	_ = resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Shut down with 5 s drain budget.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)

	// After shutdown, new connections must fail.
	client := &http.Client{Timeout: 2 * time.Second}
	resp2, err := client.Get(fmt.Sprintf("http://%s/health", addr))
	if err == nil {
		_ = resp2.Body.Close()
	}
	require.Error(t, err, "expected connection refused after shutdown")
}

// TestServer_DrainsInFlightRequests verifies that an in-flight request completes before shutdown returns.
func TestServer_DrainsInFlightRequests(t *testing.T) {
	logger := zaptest.NewLogger(t)
	s, addr := startServer(t, logger, slowHandler(), nil)

	var requestDone atomic.Bool
	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/slow", addr))
		if err == nil {
			_ = resp.Body.Close()
		}
		requestDone.Store(true)
	}()

	// Give the goroutine time to connect before we start shutting down.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), httpserver.ShutdownTimeout)
	defer cancel()
	s.Shutdown(ctx)

	// Request must have completed before Shutdown returned.
	assert.True(t, requestDone.Load(), "in-flight request must complete before Shutdown returns")
}

// TestServer_ClosersCalledOnShutdown verifies that all registered Closers are called.
func TestServer_ClosersCalledOnShutdown(t *testing.T) {
	logger := zaptest.NewLogger(t)

	redis := &mockCloser{name: "redis"}
	db := &mockCloser{name: "postgres"}

	s, _ := startServer(t, logger, healthHandler(), []httpserver.Closer{redis, db})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)

	assert.True(t, redis.closed.Load(), "redis.Close() must be called")
	assert.True(t, db.closed.Load(), "db.Close() must be called")
}

// TestServer_ClosersCalledAfterHTTPDrain verifies closer ordering:
// HTTP drains first, then closers run.
func TestServer_ClosersCalledAfterHTTPDrain(t *testing.T) {
	logger := zaptest.NewLogger(t)

	var requestDone atomic.Bool
	var requestDoneAtClose bool

	s := httpserver.New(logger,
		[]*http.Server{{Addr: ":0", Handler: slowHandler(), ReadHeaderTimeout: 5 * time.Second}},
		[]httpserver.Closer{&orderCloser{
			name: "redis",
			closeFn: func() error {
				requestDoneAtClose = requestDone.Load()
				return nil
			},
		}},
	)
	listeners, err := s.Start()
	require.NoError(t, err)
	addr := listeners[0].Addr().String()

	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/slow", addr))
		if err == nil {
			_ = resp.Body.Close()
		}
		requestDone.Store(true)
	}()

	// Give the goroutine time to connect before shutdown begins.
	time.Sleep(20 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), httpserver.ShutdownTimeout)
	defer cancel()
	s.Shutdown(ctx)

	assert.True(t, requestDoneAtClose, "closer must run after HTTP drain completes")
}

// orderCloser is a Closer that delegates to a function.
type orderCloser struct {
	name    string
	closeFn func() error
}

func (o *orderCloser) Name() string { return o.name }
func (o *orderCloser) Close() error { return o.closeFn() }

// TestServer_MultipleServers verifies that multiple http.Server instances all shut down.
func TestServer_MultipleServers(t *testing.T) {
	logger := zaptest.NewLogger(t)

	publicSrv := &http.Server{Addr: ":0", Handler: healthHandler(), ReadHeaderTimeout: 5 * time.Second}
	adminSrv := &http.Server{Addr: ":0", Handler: healthHandler(), ReadHeaderTimeout: 5 * time.Second}

	s := httpserver.New(logger, []*http.Server{publicSrv, adminSrv}, nil)
	listeners, err := s.Start()
	require.NoError(t, err)
	require.Len(t, listeners, 2)

	publicAddr := listeners[0].Addr().String()
	adminAddr := listeners[1].Addr().String()

	// Both ports respond.
	for _, addr := range []string{publicAddr, adminAddr} {
		resp, err := http.Get(fmt.Sprintf("http://%s/health", addr))
		require.NoError(t, err)
		_ = resp.Body.Close()
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	s.Shutdown(ctx)

	// Both ports refuse connections after shutdown.
	client := &http.Client{Timeout: 2 * time.Second}
	for _, addr := range []string{publicAddr, adminAddr} {
		resp, err := client.Get(fmt.Sprintf("http://%s/health", addr))
		if err == nil {
			_ = resp.Body.Close()
		}
		require.Error(t, err, "expected connection refused on %s", addr)
	}
}

// TestServer_ListenError verifies that Start returns an error for invalid addresses.
func TestServer_ListenError(t *testing.T) {
	logger := zaptest.NewLogger(t)

	// Pick an already-bound port to force a bind error.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer func() { _ = ln.Close() }()
	usedAddr := ln.Addr().String()

	srv := &http.Server{Addr: usedAddr, ReadHeaderTimeout: 5 * time.Second}
	s := httpserver.New(logger, []*http.Server{srv}, nil)
	_, err = s.Start()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "listen")
}
