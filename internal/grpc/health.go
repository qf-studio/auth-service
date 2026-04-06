package grpc

import (
	"context"

	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/qf-studio/auth-service/internal/health"
)

// HealthServer implements grpc.health.v1.Health by delegating to the
// existing internal/health.Service.
type HealthServer struct {
	healthpb.UnimplementedHealthServer
	healthSvc *health.Service
}

// NewHealthServer creates a HealthServer backed by the given health.Service.
func NewHealthServer(svc *health.Service) *HealthServer {
	return &HealthServer{healthSvc: svc}
}

// Check implements the gRPC Health/Check RPC.
// An empty or "auth.v1.AuthService" service name checks overall readiness.
func (h *HealthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	svc := req.GetService()
	if svc != "" && svc != "auth.v1.AuthService" {
		return nil, status.Errorf(codes.NotFound, "unknown service: %s", svc)
	}

	resp := h.healthSvc.Readiness(ctx)

	serving := healthpb.HealthCheckResponse_NOT_SERVING
	if resp.Status == health.StatusHealthy {
		serving = healthpb.HealthCheckResponse_SERVING
	}

	return &healthpb.HealthCheckResponse{Status: serving}, nil
}

// Watch is not implemented; returns Unimplemented per the gRPC health spec recommendation.
func (h *HealthServer) Watch(_ *healthpb.HealthCheckRequest, _ healthpb.Health_WatchServer) error {
	return status.Error(codes.Unimplemented, "watch is not supported")
}
