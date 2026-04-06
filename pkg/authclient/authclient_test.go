package authclient_test

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	"github.com/qf-studio/auth-service/pkg/authclient"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

const bufSize = 1024 * 1024

// ── Mock server ───────────────────────────────────────────────────────────────

type mockAuthServer struct {
	authv1.UnimplementedAuthServiceServer

	validateFn   func(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error)
	getUserFn    func(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error)
	checkPermFn  func(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error)
	introspectFn func(ctx context.Context, req *authv1.IntrospectTokenRequest) (*authv1.IntrospectTokenResponse, error)
}

func (m *mockAuthServer) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if m.validateFn != nil {
		return m.validateFn(ctx, req)
	}
	return &authv1.ValidateTokenResponse{Valid: false}, nil
}

func (m *mockAuthServer) GetUser(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if m.getUserFn != nil {
		return m.getUserFn(ctx, req)
	}
	return nil, status.Error(codes.Unimplemented, "not configured")
}

func (m *mockAuthServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if m.checkPermFn != nil {
		return m.checkPermFn(ctx, req)
	}
	return &authv1.CheckPermissionResponse{Allowed: false}, nil
}

func (m *mockAuthServer) IntrospectToken(ctx context.Context, req *authv1.IntrospectTokenRequest) (*authv1.IntrospectTokenResponse, error) {
	if m.introspectFn != nil {
		return m.introspectFn(ctx, req)
	}
	return &authv1.IntrospectTokenResponse{Active: false}, nil
}

// ── Test helpers ──────────────────────────────────────────────────────────────

func setupClient(t *testing.T, srv authv1.AuthServiceServer) *authclient.Client {
	t.Helper()

	lis := bufconn.Listen(bufSize)
	gs := grpc.NewServer()
	authv1.RegisterAuthServiceServer(gs, srv)

	go func() {
		if err := gs.Serve(lis); err != nil {
			// stopped during cleanup
		}
	}()
	t.Cleanup(gs.Stop)

	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(_ context.Context, _ string) (net.Conn, error) {
			return lis.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	return authclient.NewFromConn(conn, authclient.WithInsecure())
}

// ── ValidateToken tests ───────────────────────────────────────────────────────

func TestValidateToken_Valid(t *testing.T) {
	srv := &mockAuthServer{
		validateFn: func(_ context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
			require.Equal(t, "qf_at_testtoken", req.GetAccessToken())
			return &authv1.ValidateTokenResponse{
				Valid: true,
				Claims: &authv1.TokenClaims{
					Subject:    "user-123",
					Roles:      []string{"admin"},
					Scopes:     []string{"read", "write"},
					ClientType: "user",
					TokenId:    "tok-abc",
				},
			}, nil
		},
	}

	client := setupClient(t, srv)
	result, err := client.ValidateToken(context.Background(), "qf_at_testtoken")

	require.NoError(t, err)
	assert.True(t, result.Valid)
	assert.Equal(t, "user-123", result.Claims.Subject)
	assert.Equal(t, []string{"admin"}, result.Claims.Roles)
	assert.Equal(t, []string{"read", "write"}, result.Claims.Scopes)
	assert.Equal(t, "user", result.Claims.ClientType)
	assert.Equal(t, "tok-abc", result.Claims.TokenID)
}

func TestValidateToken_Invalid(t *testing.T) {
	srv := &mockAuthServer{
		validateFn: func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
			return &authv1.ValidateTokenResponse{Valid: false}, nil
		},
	}

	client := setupClient(t, srv)
	result, err := client.ValidateToken(context.Background(), "bad-token")

	require.NoError(t, err)
	assert.False(t, result.Valid)
	assert.Nil(t, result.Claims)
}

func TestValidateToken_TransportError(t *testing.T) {
	srv := &mockAuthServer{
		validateFn: func(_ context.Context, _ *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "empty token")
		},
	}

	client := setupClient(t, srv)
	// Non-retryable error should be returned immediately.
	_, err := client.ValidateToken(context.Background(), "")
	require.Error(t, err)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// ── IntrospectToken tests ─────────────────────────────────────────────────────

func TestIntrospectToken_Active(t *testing.T) {
	srv := &mockAuthServer{
		introspectFn: func(_ context.Context, req *authv1.IntrospectTokenRequest) (*authv1.IntrospectTokenResponse, error) {
			return &authv1.IntrospectTokenResponse{
				Active: true,
				Claims: &authv1.TokenClaims{Subject: "user-456"},
			}, nil
		},
	}

	client := setupClient(t, srv)
	result, err := client.IntrospectToken(context.Background(), "qf_at_active")

	require.NoError(t, err)
	assert.True(t, result.Active)
	assert.Equal(t, "user-456", result.Claims.Subject)
}

func TestIntrospectToken_Inactive(t *testing.T) {
	srv := &mockAuthServer{
		introspectFn: func(_ context.Context, _ *authv1.IntrospectTokenRequest) (*authv1.IntrospectTokenResponse, error) {
			return &authv1.IntrospectTokenResponse{Active: false}, nil
		},
	}

	client := setupClient(t, srv)
	result, err := client.IntrospectToken(context.Background(), "expired-token")

	require.NoError(t, err)
	assert.False(t, result.Active)
	assert.Nil(t, result.Claims)
}

// ── CheckPermission tests ─────────────────────────────────────────────────────

func TestCheckPermission_Allowed(t *testing.T) {
	srv := &mockAuthServer{
		checkPermFn: func(_ context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
			assert.Equal(t, "admin-user", req.GetSubject())
			assert.Equal(t, "resource", req.GetObject())
			assert.Equal(t, "read", req.GetAction())
			return &authv1.CheckPermissionResponse{Allowed: true}, nil
		},
	}

	client := setupClient(t, srv)
	allowed, err := client.CheckPermission(context.Background(), "admin-user", "resource", "read")

	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestCheckPermission_Denied(t *testing.T) {
	srv := &mockAuthServer{
		checkPermFn: func(_ context.Context, _ *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
			return &authv1.CheckPermissionResponse{Allowed: false}, nil
		},
	}

	client := setupClient(t, srv)
	allowed, err := client.CheckPermission(context.Background(), "regular-user", "secret", "write")

	require.NoError(t, err)
	assert.False(t, allowed)
}

func TestCheckPermission_TransportError(t *testing.T) {
	srv := &mockAuthServer{
		checkPermFn: func(_ context.Context, _ *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
			return nil, status.Error(codes.InvalidArgument, "missing fields")
		},
	}

	client := setupClient(t, srv)
	_, err := client.CheckPermission(context.Background(), "", "", "")
	require.Error(t, err)
}

// ── GetUser tests ─────────────────────────────────────────────────────────────

func TestGetUser_Found(t *testing.T) {
	srv := &mockAuthServer{
		getUserFn: func(_ context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
			require.Equal(t, "user-123", req.GetUserId())
			return &authv1.GetUserResponse{
				User: &authv1.User{
					Id:            "user-123",
					Email:         "test@example.com",
					Name:          "Test User",
					Roles:         []string{"user"},
					EmailVerified: true,
				},
			}, nil
		},
	}

	client := setupClient(t, srv)
	user, err := client.GetUser(context.Background(), "user-123")

	require.NoError(t, err)
	assert.Equal(t, "user-123", user.ID)
	assert.Equal(t, "test@example.com", user.Email)
	assert.Equal(t, "Test User", user.Name)
	assert.Equal(t, []string{"user"}, user.Roles)
	assert.True(t, user.EmailVerified)
	assert.False(t, user.Locked)
}

func TestGetUser_NotFound(t *testing.T) {
	srv := &mockAuthServer{
		getUserFn: func(_ context.Context, _ *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
			return nil, status.Error(codes.NotFound, "user not found")
		},
	}

	client := setupClient(t, srv)
	_, err := client.GetUser(context.Background(), "nonexistent")

	require.Error(t, err)
	assert.Equal(t, codes.NotFound, status.Code(err))
}
