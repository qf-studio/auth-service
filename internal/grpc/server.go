// Package grpc provides the gRPC server for the auth service.
// It exposes token validation, RBAC checks, and health over gRPC
// alongside the existing HTTP servers.
package grpc

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/keepalive"

	"github.com/qf-studio/auth-service/internal/config"
)

// Server wraps a gRPC server with lifecycle management.
type Server struct {
	srv      *grpc.Server
	listener net.Listener
	logger   *zap.Logger
	port     int
}

// Deps holds the dependencies injected into the gRPC server.
type Deps struct {
	Logger *zap.Logger
}

// New creates a gRPC server configured with keepalive, optional TLS, and health checking.
func New(cfg config.GRPCConfig, deps Deps) (*Server, error) {
	opts := []grpc.ServerOption{
		grpc.KeepaliveParams(keepalive.ServerParameters{
			Time:                  cfg.KeepaliveTime,
			Timeout:               cfg.KeepaliveTimeout,
			MaxConnectionIdle:     cfg.MaxConnectionIdle,
			MaxConnectionAge:      cfg.MaxConnectionAge,
			MaxConnectionAgeGrace: cfg.MaxConnectionAgeGrace,
		}),
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             30 * time.Second,
			PermitWithoutStream: true,
		}),
	}

	if cfg.TLSCertPath != "" && cfg.TLSKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCertPath, cfg.TLSKeyPath)
		if err != nil {
			return nil, fmt.Errorf("grpc tls: %w", err)
		}
		opts = append(opts, grpc.Creds(credentials.NewTLS(&tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS13,
		})))
	}

	srv := grpc.NewServer(opts...)

	// Register gRPC health checking service.
	healthSrv := health.NewServer()
	healthpb.RegisterHealthServer(srv, healthSrv)
	healthSrv.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)

	return &Server{
		srv:    srv,
		logger: deps.Logger,
		port:   cfg.Port,
	}, nil
}

// Start begins listening on the configured port and serves gRPC requests.
// It blocks in a goroutine and returns immediately.
func (s *Server) Start() error {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return fmt.Errorf("grpc listen :%d: %w", s.port, err)
	}
	s.listener = ln

	go func() {
		s.logger.Info("grpc server listening", zap.String("addr", ln.Addr().String()))
		if err := s.srv.Serve(ln); err != nil {
			s.logger.Error("grpc server error", zap.Error(err))
		}
	}()

	return nil
}

// GracefulStop drains in-flight RPCs then stops the server.
func (s *Server) GracefulStop(_ context.Context) {
	s.srv.GracefulStop()
}

// Name implements httpserver.Closer for graceful shutdown ordering.
func (s *Server) Name() string { return "grpc" }

// Close stops the gRPC server gracefully.
func (s *Server) Close() error {
	s.srv.GracefulStop()
	return nil
}

// GRPCServer returns the underlying *grpc.Server for service registration.
func (s *Server) GRPCServer() *grpc.Server {
	return s.srv
}
