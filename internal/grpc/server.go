// Package grpc implements the gRPC server for the auth service, providing
// token validation, user lookup, and permission checking for internal
// service-to-service communication on port 4002.
package grpc

import (
	"context"
	"fmt"
	"net"

	"go.uber.org/zap"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/rbac"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/token"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// Server manages the gRPC server lifecycle including startup and graceful shutdown.
type Server struct {
	grpcServer *grpc.Server
	listener   net.Listener
	logger     *zap.Logger
	port       int
}

// ServerDeps groups all dependencies needed to construct the gRPC server.
type ServerDeps struct {
	TokenSvc  *token.Service
	RBACSvc   rbac.Enforcer
	UserRepo  storage.UserRepository
	HealthSvc *health.Service
	Logger    *zap.Logger
	Port      int
	Metrics   MetricsRecorder
}

// NewServer creates a gRPC server with all services registered and interceptors
// wired. Call Start() to begin serving and GracefulStop() to shut down.
func NewServer(deps ServerDeps) (*Server, error) {
	if deps.Logger == nil {
		return nil, fmt.Errorf("grpc: logger is required")
	}
	if deps.Port <= 0 {
		return nil, fmt.Errorf("grpc: port must be positive")
	}

	// Build interceptor chains.
	unaryInterceptors := []grpc.UnaryServerInterceptor{
		UnaryLoggingInterceptor(deps.Logger),
	}
	streamInterceptors := []grpc.StreamServerInterceptor{
		StreamLoggingInterceptor(deps.Logger),
	}

	if deps.Metrics != nil {
		unaryInterceptors = append(unaryInterceptors, UnaryMetricsInterceptor(deps.Metrics))
		streamInterceptors = append(streamInterceptors, StreamMetricsInterceptor(deps.Metrics))
	}

	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(unaryInterceptors...),
		grpc.ChainStreamInterceptor(streamInterceptors...),
	)

	// Register AuthService.
	authSvc := NewAuthServiceServer(deps.TokenSvc, deps.RBACSvc, deps.UserRepo, deps.Logger)
	authv1.RegisterAuthServiceServer(gs, authSvc)

	// Register Health service.
	healthSvr := NewHealthServer(deps.HealthSvc)
	healthpb.RegisterHealthServer(gs, healthSvr)

	return &Server{
		grpcServer: gs,
		logger:     deps.Logger,
		port:       deps.Port,
	}, nil
}

// Start binds to the configured port and begins serving gRPC requests in the
// background. Returns the listener for use in tests or for inspecting the
// bound address (useful when port is 0).
func (s *Server) Start() (net.Listener, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", s.port))
	if err != nil {
		return nil, fmt.Errorf("grpc: listen :%d: %w", s.port, err)
	}
	s.listener = ln

	go func() {
		s.logger.Info("grpc server listening", zap.String("addr", ln.Addr().String()))
		if err := s.grpcServer.Serve(ln); err != nil {
			s.logger.Error("grpc server error", zap.Error(err))
		}
	}()

	return ln, nil
}

// GracefulStop gracefully drains in-flight RPCs and stops the server.
// The context is used for logging only; grpc.Server.GracefulStop blocks
// until all RPCs complete (no deadline support).
func (s *Server) GracefulStop(_ context.Context) {
	s.logger.Info("grpc server shutting down")
	s.grpcServer.GracefulStop()
	s.logger.Info("grpc server stopped")
}

// Stop immediately stops the server without waiting for in-flight RPCs.
func (s *Server) Stop() {
	s.grpcServer.Stop()
}

// GRPCServer returns the underlying grpc.Server for testing or advanced use.
func (s *Server) GRPCServer() *grpc.Server {
	return s.grpcServer
}
