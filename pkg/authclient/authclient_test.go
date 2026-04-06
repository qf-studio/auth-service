package authclient_test

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/qf-studio/auth-service/pkg/authclient"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const bufSize = 1024 * 1024

// fakeAuthServer implements the AuthService gRPC server for testing.
type fakeAuthServer struct {
	authv1.UnimplementedAuthServiceServer
	validateFn   func(context.Context, *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error)
	checkPermFn  func(context.Context, *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error)
}

func (f *fakeAuthServer) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if f.validateFn != nil {
		return f.validateFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not configured")
}

func (f *fakeAuthServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if f.checkPermFn != nil {
		return f.checkPermFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not configured")
}

// testEnv holds a bufconn listener, gRPC server, and client for integration tests.
type testEnv struct {
	srv    *grpc.Server
	lis    *bufconn.Listener
	client *authclient.Client
	fake   *fakeAuthServer
}

func newTestEnv(t *testing.T, opts ...authclient.Option) *testEnv {
	t.Helper()
	lis := bufconn.Listen(bufSize)
	srv := grpc.NewServer()
	fake := &fakeAuthServer{}
	authv1.RegisterAuthServiceServer(srv, fake)

	go func() {
		if err := srv.Serve(lis); err != nil {
			// Server stopped; expected during cleanup.
		}
	}()

	conn, err := grpc.NewClient("passthrough:///bufconn",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return lis.DialContext(ctx)
		}),
	)
	require.NoError(t, err)

	allOpts := append([]authclient.Option{authclient.WithInsecure()}, opts...)
	client := authclient.NewFromConn(conn, allOpts...)

	t.Cleanup(func() {
		_ = client.Close()
		_ = conn.Close()
		srv.GracefulStop()
		_ = lis.Close()
	})

	return &testEnv{srv: srv, lis: lis, client: client, fake: fake}
}

// --- ValidateToken tests ---

func TestValidateToken_Valid(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	exp := now.Add(15 * time.Minute)

	env := newTestEnv(t)
	env.fake.validateFn = func(_ context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		assert.Equal(t, "qf_at_test123", req.GetToken())
		return &authv1.ValidateTokenResponse{
			Valid: true,
			Claims: &authv1.TokenClaims{
				Subject:    "user-1",
				Roles:      []string{"admin", "user"},
				Scopes:     []string{"read:users"},
				ClientType: "user",
				TokenId:    "jti-abc",
				ExpiresAt:  timestamppb.New(exp),
				IssuedAt:   timestamppb.New(now),
			},
		}, nil
	}

	claims, err := env.client.ValidateToken(context.Background(), "qf_at_test123")
	require.NoError(t, err)

	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, []string{"admin", "user"}, claims.Roles)
	assert.Equal(t, []string{"read:users"}, claims.Scopes)
	assert.Equal(t, "user", claims.ClientType)
	assert.Equal(t, "jti-abc", claims.TokenID)
	assert.Equal(t, exp.UTC(), claims.ExpiresAt.UTC())
	assert.Equal(t, now.UTC(), claims.IssuedAt.UTC())
}

func TestValidateToken_Invalid(t *testing.T) {
	env := newTestEnv(t)
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		return &authv1.ValidateTokenResponse{Valid: false}, nil
	}

	_, err := env.client.ValidateToken(context.Background(), "bad-token")
	assert.ErrorIs(t, err, authclient.ErrTokenInvalid)
}

func TestValidateToken_Unauthenticated(t *testing.T) {
	env := newTestEnv(t)
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		return nil, status.Error(codes.Unauthenticated, "missing credentials")
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.ErrorIs(t, err, authclient.ErrUnauthenticated)
}

func TestValidateToken_ServerError(t *testing.T) {
	env := newTestEnv(t)
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		return nil, status.Error(codes.Internal, "db down")
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.Error(t, err)
	assert.False(t, errors.Is(err, authclient.ErrTokenInvalid))
}

// --- CheckPermission tests ---

func TestCheckPermission_Allowed(t *testing.T) {
	env := newTestEnv(t)
	env.fake.checkPermFn = func(_ context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
		assert.Equal(t, "user-1", req.GetSubject())
		assert.Equal(t, "users", req.GetObject())
		assert.Equal(t, "read", req.GetAction())
		return &authv1.CheckPermissionResponse{Allowed: true}, nil
	}

	err := env.client.CheckPermission(context.Background(), "user-1", "users", "read")
	assert.NoError(t, err)
}

func TestCheckPermission_Denied(t *testing.T) {
	env := newTestEnv(t)
	env.fake.checkPermFn = func(_ context.Context, _ *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
		return &authv1.CheckPermissionResponse{Allowed: false}, nil
	}

	err := env.client.CheckPermission(context.Background(), "user-2", "admin", "write")
	assert.ErrorIs(t, err, authclient.ErrPermissionDenied)
}

func TestCheckPermission_ServerError(t *testing.T) {
	env := newTestEnv(t)
	env.fake.checkPermFn = func(_ context.Context, _ *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
		return nil, status.Error(codes.Internal, "rbac engine failure")
	}

	err := env.client.CheckPermission(context.Background(), "user-1", "users", "read")
	assert.Error(t, err)
	assert.False(t, errors.Is(err, authclient.ErrPermissionDenied))
}

// --- Retry tests ---

func TestValidateToken_RetriesOnUnavailable(t *testing.T) {
	env := newTestEnv(t, authclient.WithMaxRetries(2), authclient.WithRetryBackoff(10*time.Millisecond, 50*time.Millisecond))

	calls := 0
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		calls++
		if calls < 3 {
			return nil, status.Error(codes.Unavailable, "temporarily unavailable")
		}
		return &authv1.ValidateTokenResponse{
			Valid:  true,
			Claims: &authv1.TokenClaims{Subject: "user-1"},
		}, nil
	}

	claims, err := env.client.ValidateToken(context.Background(), "token")
	require.NoError(t, err)
	assert.Equal(t, "user-1", claims.Subject)
	assert.Equal(t, 3, calls)
}

func TestValidateToken_NoRetryOnNonRetryableError(t *testing.T) {
	env := newTestEnv(t, authclient.WithMaxRetries(3))

	calls := 0
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		calls++
		return nil, status.Error(codes.InvalidArgument, "bad request")
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should not retry non-retryable errors")
}

func TestValidateToken_RetriesExhausted(t *testing.T) {
	env := newTestEnv(t, authclient.WithMaxRetries(2), authclient.WithRetryBackoff(5*time.Millisecond, 20*time.Millisecond))

	calls := 0
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		calls++
		return nil, status.Error(codes.Unavailable, "still down")
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Equal(t, 3, calls) // initial + 2 retries
}

// --- Timeout tests ---

func TestValidateToken_Timeout(t *testing.T) {
	env := newTestEnv(t, authclient.WithTimeout(50*time.Millisecond), authclient.WithMaxRetries(0))
	env.fake.validateFn = func(ctx context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return &authv1.ValidateTokenResponse{Valid: true}, nil
		}
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.Error(t, err)
}

// --- Options tests ---

func TestWithMaxRetries_Zero_DisablesRetries(t *testing.T) {
	env := newTestEnv(t, authclient.WithMaxRetries(0))

	calls := 0
	env.fake.validateFn = func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
		calls++
		return nil, status.Error(codes.Unavailable, "down")
	}

	_, err := env.client.ValidateToken(context.Background(), "token")
	assert.Error(t, err)
	assert.Equal(t, 1, calls)
}

func TestNewFromConn_CloseIsNoOp(t *testing.T) {
	env := newTestEnv(t)
	// Close should not error since it's a no-op for NewFromConn clients.
	err := env.client.Close()
	assert.NoError(t, err)
}
