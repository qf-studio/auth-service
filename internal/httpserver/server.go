// Package httpserver manages dual-port HTTP lifecycle with graceful shutdown.
package httpserver

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
)

// ShutdownTimeout is the maximum time given to in-flight requests to complete.
const ShutdownTimeout = 15 * time.Second

// Closer is any resource that must be released during shutdown (e.g. Redis, DB).
type Closer interface {
	// Name returns a human-readable label used in log output.
	Name() string
	// Close releases the resource. Errors are logged but not fatal.
	Close() error
}

// Server manages one or more http.Server instances and orchestrates shutdown.
type Server struct {
	servers []*http.Server
	closers []Closer
	logger  *zap.Logger
}

// New creates a Server from the provided http.Server instances.
// closers are released in order after HTTP servers have stopped.
func New(logger *zap.Logger, servers []*http.Server, closers []Closer) *Server {
	return &Server{
		servers: servers,
		closers: closers,
		logger:  logger,
	}
}

// Start launches all HTTP servers in the background and returns their listeners.
// Each server listens on its Addr; a ":0" address will be assigned a random port.
// Returns an error if any server fails to bind.
func (s *Server) Start() ([]*net.TCPListener, error) {
	listeners := make([]*net.TCPListener, len(s.servers))
	for i, srv := range s.servers {
		ln, err := net.Listen("tcp", srv.Addr)
		if err != nil {
			// Close any listeners already opened.
			for _, opened := range listeners[:i] {
				_ = opened.Close()
			}
			return nil, fmt.Errorf("listen %s: %w", srv.Addr, err)
		}
		tcpLn := ln.(*net.TCPListener)
		listeners[i] = tcpLn

		go func(srv *http.Server, ln net.Listener) {
			s.logger.Info("http server listening", zap.String("addr", ln.Addr().String()))
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				s.logger.Error("http server error", zap.Error(err))
			}
		}(srv, tcpLn)
	}
	return listeners, nil
}

// Shutdown gracefully stops all HTTP servers and then releases closers.
// The provided context controls the maximum wait for in-flight requests to drain.
func (s *Server) Shutdown(ctx context.Context) {
	// Stop accepting new connections on all servers simultaneously.
	for _, srv := range s.servers {
		addr := srv.Addr
		s.logger.Info("shutting down http server", zap.String("addr", addr))
		if err := srv.Shutdown(ctx); err != nil {
			s.logger.Error("http server shutdown error",
				zap.String("addr", addr),
				zap.Error(err),
			)
		}
	}

	// Release downstream resources after HTTP is fully drained.
	for _, c := range s.closers {
		s.logger.Info("closing resource", zap.String("name", c.Name()))
		if err := c.Close(); err != nil {
			s.logger.Error("resource close error",
				zap.String("name", c.Name()),
				zap.Error(err),
			)
		}
	}
}
