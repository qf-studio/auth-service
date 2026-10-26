package grpc

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const internalFakeToken = "fake-grpc-client-token-aaaaaaaaaaaaaaaa" //nolint:gosec // G101: obviously fake test value

type fakeServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (f *fakeServerStream) Context() context.Context { return f.ctx }

func TestAuthenticator_WarnIsRateLimitedPerMethod(t *testing.T) {
	core, logs := observer.New(zapcore.WarnLevel)
	a, err := NewAuthenticator(AuthModeWarn, []string{internalFakeToken}, zap.New(core))
	require.NoError(t, err)
	now := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	a.now = func() time.Time { return now }

	ctx := context.Background()
	require.NoError(t, a.check(ctx, "/auth.v1.AuthService/GetUser"))
	require.NoError(t, a.check(ctx, "/auth.v1.AuthService/GetUser"))
	assert.Equal(t, 1, logs.Len(), "second call inside the window is suppressed")

	require.NoError(t, a.check(ctx, "/auth.v1.AuthService/CheckPermission"))
	assert.Equal(t, 2, logs.Len(), "a different method logs independently")

	now = now.Add(authWarnInterval - time.Second)
	require.NoError(t, a.check(ctx, "/auth.v1.AuthService/GetUser"))
	assert.Equal(t, 2, logs.Len())

	now = now.Add(time.Second)
	require.NoError(t, a.check(ctx, "/auth.v1.AuthService/GetUser"))
	assert.Equal(t, 3, logs.Len(), "logs again once the interval has elapsed")
}

func TestAuthenticator_Stream(t *testing.T) {
	a, err := NewAuthenticator(AuthModeEnforce, []string{internalFakeToken}, zap.NewNop())
	require.NoError(t, err)
	info := &grpc.StreamServerInfo{FullMethod: "/auth.v1.AuthService/Watch"}

	called := false
	handler := func(_ interface{}, _ grpc.ServerStream) error { called = true; return nil }

	err = a.Stream()(nil, &fakeServerStream{ctx: context.Background()}, info, handler)
	assert.Equal(t, codes.Unauthenticated, status.Code(err))
	assert.False(t, called)

	md := metadata.Pairs("authorization", "Bearer "+internalFakeToken)
	ctx := metadata.NewIncomingContext(context.Background(), md)
	require.NoError(t, a.Stream()(nil, &fakeServerStream{ctx: ctx}, info, handler))
	assert.True(t, called)

	// Health streams (Watch) are exempt.
	called = false
	healthInfo := &grpc.StreamServerInfo{FullMethod: "/grpc.health.v1.Health/Watch"}
	require.NoError(t, a.Stream()(nil, &fakeServerStream{ctx: context.Background()}, healthInfo, handler))
	assert.True(t, called)
}

func TestAuthenticator_NilLogger(t *testing.T) {
	_, err := NewAuthenticator(AuthModeOff, nil, nil)
	require.Error(t, err)
}
