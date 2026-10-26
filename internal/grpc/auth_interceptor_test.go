package grpc_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	grpcpkg "github.com/qf-studio/auth-service/internal/grpc"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// Obviously fake tokens (>= 32 bytes) — never use realistic secrets in tests.
const (
	fakeClientToken      = "fake-grpc-client-token-aaaaaaaaaaaaaaaa" //nolint:gosec // G101: obviously fake test value
	fakeOtherClientToken = "fake-grpc-client-token-bbbbbbbbbbbbbbbb" //nolint:gosec // G101: obviously fake test value
)

func authDeps(t *testing.T, mode grpcpkg.AuthMode, logger *zap.Logger) grpcpkg.ServerDeps {
	t.Helper()
	deps, _ := defaultTestDeps(t)
	deps.AuthMode = mode
	deps.ClientTokens = []string{fakeClientToken, fakeOtherClientToken}
	if logger != nil {
		deps.Logger = logger
	}
	return deps
}

func withBearer(token string) context.Context {
	return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+token)
}

func TestAuth_Enforce(t *testing.T) {
	tests := []struct {
		name     string
		ctx      context.Context
		wantCode codes.Code
	}{
		{"no token", context.Background(), codes.Unauthenticated},
		{"valid token", withBearer(fakeClientToken), codes.OK},
		{"second configured token", withBearer(fakeOtherClientToken), codes.OK},
		{"wrong token", withBearer("fake-grpc-client-token-cccccccccccccccc"), codes.Unauthenticated},
		{"prefix of valid token", withBearer(fakeClientToken[:10]), codes.Unauthenticated},
		{"lowercase scheme", metadata.AppendToOutgoingContext(context.Background(), "authorization", "bearer "+fakeClientToken), codes.OK},
		{"wrong scheme", metadata.AppendToOutgoingContext(context.Background(), "authorization", "Basic "+fakeClientToken), codes.Unauthenticated},
		{"no scheme", metadata.AppendToOutgoingContext(context.Background(), "authorization", fakeClientToken), codes.Unauthenticated},
		{"empty bearer", metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "), codes.Unauthenticated},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeEnforce, nil))
			_, err := client.ValidateToken(tt.ctx, &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
			assert.Equal(t, tt.wantCode, status.Code(err))
		})
	}
}

func TestAuth_Enforce_AllAuthServiceMethods(t *testing.T) {
	client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeEnforce, nil))
	ctx := context.Background()

	_, err := client.GetUser(ctx, &authv1.GetUserRequest{UserId: "user-123"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = client.CheckPermission(ctx, &authv1.CheckPermissionRequest{Subject: "admin-user", Object: "r", Action: "a"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	_, err = client.IntrospectToken(ctx, &authv1.IntrospectTokenRequest{AccessToken: "qf_at_fake"})
	assert.Equal(t, codes.Unauthenticated, status.Code(err))

	_, err = client.GetUser(withBearer(fakeClientToken), &authv1.GetUserRequest{UserId: "user-123"})
	assert.NoError(t, err)
}

func TestAuth_Warn_AllowsAndLogs(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeWarn, zap.New(core)))

	_, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
	require.NoError(t, err)

	entries := logs.FilterMessageSnippet("not authenticated").All()
	require.Len(t, entries, 1)
	fields := entries[0].ContextMap()
	assert.Equal(t, "/auth.v1.AuthService/ValidateToken", fields["grpc.method"])
	assert.Equal(t, "missing", fields["reason"])
	assert.NotEmpty(t, fields["peer"])
}

func TestAuth_Warn_ValidTokenDoesNotLog(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeWarn, zap.New(core)))

	_, err := client.ValidateToken(withBearer(fakeClientToken), &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
	require.NoError(t, err)
	assert.Zero(t, logs.Len())
}

func TestAuth_Warn_InvalidTokenLoggedWithoutSecret(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeWarn, zap.New(core)))

	const bad = "fake-grpc-client-token-zzzzzzzzzzzzzzzz"
	_, err := client.ValidateToken(withBearer(bad), &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
	require.NoError(t, err)

	entries := logs.All()
	require.Len(t, entries, 1)
	assert.Equal(t, "invalid", entries[0].ContextMap()["reason"])
	assert.NotContains(t, entries[0].Message, bad)
	for _, v := range entries[0].ContextMap() {
		assert.NotContains(t, v, bad)
	}
}

func TestAuth_Off_AllowsWithoutLog(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	client, _ := setupBufConn(t, authDeps(t, grpcpkg.AuthModeOff, zap.New(core)))

	_, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
	require.NoError(t, err)
	assert.Zero(t, logs.Len())
}

func TestAuth_DefaultModeIsWarn(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	client, _ := setupBufConn(t, authDeps(t, "", zap.New(core)))

	_, err := client.ValidateToken(context.Background(), &authv1.ValidateTokenRequest{AccessToken: "qf_at_fake"})
	require.NoError(t, err)
	assert.Equal(t, 1, logs.Len())
}

func TestAuth_HealthAlwaysAllowed(t *testing.T) {
	for _, mode := range []grpcpkg.AuthMode{grpcpkg.AuthModeOff, grpcpkg.AuthModeWarn, grpcpkg.AuthModeEnforce} {
		t.Run(string(mode), func(t *testing.T) {
			core, logs := observer.New(zapcore.WarnLevel)
			_, healthClient := setupBufConn(t, authDeps(t, mode, zap.New(core)))

			resp, err := healthClient.Check(context.Background(), &healthpb.HealthCheckRequest{})
			require.NoError(t, err)
			assert.Equal(t, healthpb.HealthCheckResponse_SERVING, resp.GetStatus())
			assert.Zero(t, logs.Len(), "health checks must not trigger auth warnings")
		})
	}
}

func TestNewServer_AuthConfigErrors(t *testing.T) {
	deps, _ := defaultTestDeps(t)

	deps.AuthMode = "bogus"
	_, err := grpcpkg.NewServer(deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported auth mode")

	deps.AuthMode = grpcpkg.AuthModeEnforce
	deps.ClientTokens = nil
	_, err = grpcpkg.NewServer(deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "at least one client token")

	deps.AuthMode = grpcpkg.AuthModeWarn
	deps.ClientTokens = []string{""}
	_, err = grpcpkg.NewServer(deps)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")
}

func TestParseAuthMode(t *testing.T) {
	for _, tt := range []struct {
		in   string
		want grpcpkg.AuthMode
	}{
		{"", grpcpkg.AuthModeWarn},
		{"off", grpcpkg.AuthModeOff},
		{"WARN", grpcpkg.AuthModeWarn},
		{" enforce ", grpcpkg.AuthModeEnforce},
	} {
		got, err := grpcpkg.ParseAuthMode(tt.in)
		require.NoError(t, err, tt.in)
		assert.Equal(t, tt.want, got, tt.in)
	}
	_, err := grpcpkg.ParseAuthMode("strict")
	assert.Error(t, err)
}
