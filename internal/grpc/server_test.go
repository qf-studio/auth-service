package grpc_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/google/uuid"
	"github.com/qf-studio/auth-service/internal/audit"
	"github.com/qf-studio/auth-service/internal/config"
	"github.com/qf-studio/auth-service/internal/domain"
	grpcpkg "github.com/qf-studio/auth-service/internal/grpc"
	"github.com/qf-studio/auth-service/internal/health"
	"github.com/qf-studio/auth-service/internal/rbac"
	"github.com/qf-studio/auth-service/internal/token"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

const bufSize = 1024 * 1024

// ── Test helpers ─────────────────────────────────────────────────────────────

func newTestRedis(t *testing.T) *redis.Client {
	t.Helper()
	mr := miniredis.RunT(t)
	client := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func newTokenService(t *testing.T, rc *redis.Client) *token.Service {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cfg := config.JWTConfig{
		Algorithm:       "ES256",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		SystemSecrets:   []string{"test-secret"},
	}
	svc, err := token.NewServiceFromKey(cfg, key, rc, zap.NewNop(), audit.NopLogger{})
	require.NoError(t, err)
	return svc
}

// mockRBACEnforcer implements rbac.Enforcer for testing.
type mockRBACEnforcer struct {
	checkFn func(ctx context.Context, sub, obj, act string) (bool, error)
}

func (m *mockRBACEnforcer) CheckPermission(ctx context.Context, sub, obj, act string) (bool, error) {
	if m.checkFn != nil {
		return m.checkFn(ctx, sub, obj, act)
	}
	return false, nil
}

func (m *mockRBACEnforcer) AddPolicy(_ context.Context, _, _, _ string) error   { return nil }
func (m *mockRBACEnforcer) RemovePolicy(_ context.Context, _, _, _ string) error { return nil }
func (m *mockRBACEnforcer) AddRoleForUser(_ context.Context, _, _ string) error  { return nil }
func (m *mockRBACEnforcer) RemoveRoleForUser(_ context.Context, _, _ string) error {
	return nil
}
func (m *mockRBACEnforcer) GetRolesForUser(_ context.Context, _ string) ([]string, error) {
	return nil, nil
}
func (m *mockRBACEnforcer) LoadPolicy(_ context.Context) error { return nil }
func (m *mockRBACEnforcer) LoadFilteredPolicy(_ context.Context, _ *rbac.PolicyFilter) error {
	return nil
}

// mockUserRepo implements storage.UserRepository for testing.
type mockUserRepo struct {
	users map[string]*domain.User
}

func (m *mockUserRepo) Create(_ context.Context, user *domain.User) (*domain.User, error) {
	return user, nil
}

func (m *mockUserRepo) FindByID(_ context.Context, _ uuid.UUID, id string) (*domain.User, error) {
	if u, ok := m.users[id]; ok {
		return u, nil
	}
	return nil, fmt.Errorf("user not found")
}

func (m *mockUserRepo) FindByEmail(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepo) UpdateLastLogin(_ context.Context, _ uuid.UUID, _ string, _ time.Time) error {
	return nil
}

func (m *mockUserRepo) SetEmailVerifyToken(_ context.Context, _ uuid.UUID, _ string, _ string, _ time.Time) error {
	return nil
}

func (m *mockUserRepo) ConsumeEmailVerifyToken(_ context.Context, _ uuid.UUID, _ string) (*domain.User, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockUserRepo) UpdatePasswordHash(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}
func (m *mockUserRepo) SetForcePasswordChange(_ context.Context, _ uuid.UUID, _ string, _ bool) error {
	return nil
}
func (m *mockUserRepo) GetPasswordHistory(_ context.Context, _ uuid.UUID, _ string, _ int) ([]domain.PasswordHistoryEntry, error) {
	return nil, nil
}
func (m *mockUserRepo) AddPasswordHistory(_ context.Context, _ uuid.UUID, _, _ string) error {
	return nil
}

// mockMetricsRecorder implements grpc.MetricsRecorder for testing.
type mockMetricsRecorder struct {
	calls []metricsCall
}

type metricsCall struct {
	Method   string
	Code     string
	Duration time.Duration
}

func (m *mockMetricsRecorder) RecordGRPCRequest(method, code string, duration time.Duration) {
	m.calls = append(m.calls, metricsCall{Method: method, Code: code, Duration: duration})
}

// setupBufConn creates a gRPC server using bufconn for in-memory transport
// and returns a connected client.
func setupBufConn(t *testing.T, deps grpcpkg.ServerDeps) (authv1.AuthServiceClient, healthpb.HealthClient) {
	t.Helper()

	srv, err := grpcpkg.NewServer(deps)
	require.NoError(t, err)

	lis := bufconn.Listen(bufSize)
	go func() {
		if err := srv.GRPCServer().Serve(lis); err != nil {
			// Server stopped — expected during cleanup.
		}
	}()
	t.Cleanup(func() { srv.Stop() })

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return authv1.NewAuthServiceClient(conn), healthpb.NewHealthClient(conn)
}

func defaultTestDeps(t *testing.T) (grpcpkg.ServerDeps, *token.Service) {
	t.Helper()
	rc := newTestRedis(t)
	tokenSvc := newTokenService(t, rc)
	rbacEnforcer := &mockRBACEnforcer{
		checkFn: func(_ context.Context, sub, _, _ string) (bool, error) {
			return sub == "admin-user", nil
		},
	}
	userRepo := &mockUserRepo{
		users: map[string]*domain.User{
			"user-123": {
				ID:            "user-123",
				Email:         "test@example.com",
				Name:          "Test User",
				Roles:         []string{"user"},
				EmailVerified: true,
				CreatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
				UpdatedAt:     time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
	}
	healthSvc := health.NewService()

	deps := grpcpkg.ServerDeps{
		TokenSvc:  tokenSvc,
		RBACSvc:   rbacEnforcer,
		UserRepo:  userRepo,
		HealthSvc: healthSvc,
		Logger:    zap.NewNop(),
		Port:      4002,
	}
	return deps, tokenSvc
}

// ── Server tests ─────────────────────────────────────────────────────────────

func TestNewServer_NilLogger(t *testing.T) {
	_, err := grpcpkg.NewServer(grpcpkg.ServerDeps{Port: 4002})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "logger is required")
}

func TestNewServer_InvalidPort(t *testing.T) {
	_, err := grpcpkg.NewServer(grpcpkg.ServerDeps{Logger: zap.NewNop(), Port: 0})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "port must be positive")
}

// ── ValidateToken tests ──────────────────────────────────────────────────────

func TestValidateToken_Success(t *testing.T) {
	deps, tokenSvc := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	result, err := tokenSvc.IssueTokenPair(context.Background(), "user-123", []string{"user"}, []string{"read"}, domain.ClientTypeUser)
	require.NoError(t, err)

	resp, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{
		AccessToken: result.AccessToken,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetValid())
	assert.Equal(t, "user-123", resp.GetClaims().GetSubject())
	assert.Equal(t, []string{"user"}, resp.GetClaims().GetRoles())
	assert.Equal(t, []string{"read"}, resp.GetClaims().GetScopes())
	assert.Equal(t, "user", resp.GetClaims().GetClientType())
}

func TestValidateToken_InvalidToken(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	resp, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{
		AccessToken: "invalid-token",
	})
	require.NoError(t, err)
	assert.False(t, resp.GetValid())
}

func TestValidateToken_EmptyToken(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	_, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── GetUser tests ────────────────────────────────────────────────────────────

func TestGetUser_Success(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	resp, err := client.GetUser(context.Background(), &authv1.GetUserRequest{UserId: "user-123"})
	require.NoError(t, err)
	assert.Equal(t, "user-123", resp.GetUser().GetId())
	assert.Equal(t, "test@example.com", resp.GetUser().GetEmail())
	assert.Equal(t, "Test User", resp.GetUser().GetName())
	assert.Equal(t, []string{"user"}, resp.GetUser().GetRoles())
	assert.True(t, resp.GetUser().GetEmailVerified())
}

func TestGetUser_NotFound(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	_, err := client.GetUser(context.Background(), &authv1.GetUserRequest{UserId: "nonexistent"})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestGetUser_EmptyID(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	_, err := client.GetUser(context.Background(), &authv1.GetUserRequest{})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── CheckPermission tests ────────────────────────────────────────────────────

func TestCheckPermission_Allowed(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	resp, err := client.CheckPermission(context.Background(), &authv1.CheckPermissionRequest{
		Subject: "admin-user",
		Object:  "resource",
		Action:  "read",
	})
	require.NoError(t, err)
	assert.True(t, resp.GetAllowed())
}

func TestCheckPermission_Denied(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	resp, err := client.CheckPermission(context.Background(), &authv1.CheckPermissionRequest{
		Subject: "regular-user",
		Object:  "resource",
		Action:  "read",
	})
	require.NoError(t, err)
	assert.False(t, resp.GetAllowed())
}

func TestCheckPermission_MissingFields(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	_, err := client.CheckPermission(context.Background(), &authv1.CheckPermissionRequest{
		Subject: "user",
	})
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── IntrospectToken tests ────────────────────────────────────────────────────

func TestIntrospectToken_Active(t *testing.T) {
	deps, tokenSvc := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	result, err := tokenSvc.IssueTokenPair(context.Background(), "user-123", []string{"admin"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	resp, err := client.IntrospectToken(context.Background(), &authv1.IntrospectTokenRequest{
		AccessToken: result.AccessToken,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetActive())
	assert.Equal(t, "user-123", resp.GetClaims().GetSubject())
}

func TestIntrospectToken_Invalid(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	resp, err := client.IntrospectToken(context.Background(), &authv1.IntrospectTokenRequest{
		AccessToken: "bad-token",
	})
	require.NoError(t, err)
	assert.False(t, resp.GetActive())
}

func TestIntrospectToken_Revoked(t *testing.T) {
	deps, tokenSvc := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	result, err := tokenSvc.IssueTokenPair(context.Background(), "user-123", []string{"user"}, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	err = tokenSvc.Revoke(context.Background(), result.AccessToken)
	require.NoError(t, err)

	resp, err := client.IntrospectToken(context.Background(), &authv1.IntrospectTokenRequest{
		AccessToken: result.AccessToken,
	})
	require.NoError(t, err)
	assert.False(t, resp.GetActive())
}

// ── Health tests ─────────────────────────────────────────────────────────────

func TestHealth_Check_Serving(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	_, healthClient := setupBufConn(t, deps)

	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestHealth_Check_WithServiceName(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	_, healthClient := setupBufConn(t, deps)

	resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "auth.v1.AuthService",
	})
	require.NoError(t, err)
	assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
}

func TestHealth_Check_UnknownService(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	_, healthClient := setupBufConn(t, deps)

	_, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{
		Service: "unknown.Service",
	})
	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}

func TestHealth_Watch_Unimplemented(t *testing.T) {
	deps, _ := defaultTestDeps(t)
	_, healthClient := setupBufConn(t, deps)

	stream, err := healthClient.Watch(context.Background(), &healthpb.HealthCheckRequest{})
	require.NoError(t, err)

	_, err = stream.Recv()
	require.Error(t, err)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// ── Interceptor tests ────────────────────────────────────────────────────────

func TestInterceptor_CorrelationID_Propagated(t *testing.T) {
	deps, tokenSvc := defaultTestDeps(t)
	client, _ := setupBufConn(t, deps)

	result, err := tokenSvc.IssueTokenPair(context.Background(), "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	ctx := metadata.AppendToOutgoingContext(context.Background(), "x-request-id", "test-correlation-123")
	resp, err := client.ValidateToken(ctx, &authv1.ValidateTokenRequest{
		AccessToken: result.AccessToken,
	})
	require.NoError(t, err)
	assert.True(t, resp.GetValid())
}

func TestInterceptor_Metrics_Recorded(t *testing.T) {
	deps, tokenSvc := defaultTestDeps(t)
	recorder := &mockMetricsRecorder{}
	deps.Metrics = recorder
	client, _ := setupBufConn(t, deps)

	result, err := tokenSvc.IssueTokenPair(context.Background(), "user-123", nil, nil, domain.ClientTypeUser)
	require.NoError(t, err)

	_, err = client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{
		AccessToken: result.AccessToken,
	})
	require.NoError(t, err)

	require.NotEmpty(t, recorder.calls)
	assert.Contains(t, recorder.calls[0].Method, "ValidateToken")
	assert.Equal(t, "OK", recorder.calls[0].Code)
}
