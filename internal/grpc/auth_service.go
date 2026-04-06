package grpc

import (
	"context"
	"strings"

	"go.uber.org/zap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/qf-studio/auth-service/internal/domain"
	"github.com/qf-studio/auth-service/internal/rbac"
	"github.com/qf-studio/auth-service/internal/storage"
	"github.com/qf-studio/auth-service/internal/token"
	authv1 "github.com/qf-studio/auth-service/proto/auth/v1"
)

// accessTokenPrefix is the qf_at_ prefix on access tokens. The gRPC service
// strips this before delegating to token.Service.ValidateToken, mirroring
// the HTTP auth middleware behaviour.
const accessTokenPrefix = "qf_at_"

// AuthServiceServer implements authv1.AuthServiceServer by delegating to
// existing service-layer components.
type AuthServiceServer struct {
	authv1.UnimplementedAuthServiceServer
	tokenSvc *token.Service
	rbacSvc  rbac.Enforcer
	userRepo storage.UserRepository
	logger   *zap.Logger
}

// NewAuthServiceServer creates the gRPC AuthService implementation.
func NewAuthServiceServer(
	tokenSvc *token.Service,
	rbacSvc rbac.Enforcer,
	userRepo storage.UserRepository,
	logger *zap.Logger,
) *AuthServiceServer {
	return &AuthServiceServer{
		tokenSvc: tokenSvc,
		rbacSvc:  rbacSvc,
		userRepo: userRepo,
		logger:   logger,
	}
}

// ValidateToken verifies a JWT access token and returns its claims.
func (s *AuthServiceServer) ValidateToken(ctx context.Context, req *authv1.ValidateTokenRequest) (*authv1.ValidateTokenResponse, error) {
	if req.GetAccessToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	raw := strings.TrimPrefix(req.GetAccessToken(), accessTokenPrefix)
	claims, err := s.tokenSvc.ValidateToken(ctx, raw)
	if err != nil {
		return &authv1.ValidateTokenResponse{Valid: false}, nil
	}

	return &authv1.ValidateTokenResponse{
		Valid:  true,
		Claims: domainClaimsToProto(claims),
	}, nil
}

// GetUser retrieves a user by ID.
func (s *AuthServiceServer) GetUser(ctx context.Context, req *authv1.GetUserRequest) (*authv1.GetUserResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}

	user, err := s.userRepo.FindByID(ctx, req.GetUserId())
	if err != nil {
		s.logger.Error("grpc: user lookup failed",
			zap.String("user_id", req.GetUserId()),
			zap.Error(err),
		)
		return nil, status.Error(codes.NotFound, "user not found")
	}

	return &authv1.GetUserResponse{
		User: domainUserToProto(user),
	}, nil
}

// CheckPermission evaluates whether a subject may perform an action on an object.
func (s *AuthServiceServer) CheckPermission(ctx context.Context, req *authv1.CheckPermissionRequest) (*authv1.CheckPermissionResponse, error) {
	if req.GetSubject() == "" || req.GetObject() == "" || req.GetAction() == "" {
		return nil, status.Error(codes.InvalidArgument, "subject, object, and action are required")
	}

	allowed, err := s.rbacSvc.CheckPermission(ctx, req.GetSubject(), req.GetObject(), req.GetAction())
	if err != nil {
		s.logger.Error("grpc: permission check failed",
			zap.String("sub", req.GetSubject()),
			zap.String("obj", req.GetObject()),
			zap.String("act", req.GetAction()),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "permission check failed")
	}

	return &authv1.CheckPermissionResponse{Allowed: allowed}, nil
}

// IntrospectToken returns detailed token metadata (RFC 7662-style).
func (s *AuthServiceServer) IntrospectToken(ctx context.Context, req *authv1.IntrospectTokenRequest) (*authv1.IntrospectTokenResponse, error) {
	if req.GetAccessToken() == "" {
		return nil, status.Error(codes.InvalidArgument, "access_token is required")
	}

	raw := strings.TrimPrefix(req.GetAccessToken(), accessTokenPrefix)
	claims, err := s.tokenSvc.ValidateToken(ctx, raw)
	if err != nil {
		return &authv1.IntrospectTokenResponse{Active: false}, nil
	}

	revoked, err := s.tokenSvc.IsRevoked(ctx, claims.TokenID)
	if err != nil {
		s.logger.Error("grpc: revocation check failed",
			zap.String("token_id", claims.TokenID),
			zap.Error(err),
		)
		return nil, status.Error(codes.Internal, "revocation check failed")
	}
	if revoked {
		return &authv1.IntrospectTokenResponse{Active: false}, nil
	}

	return &authv1.IntrospectTokenResponse{
		Active: true,
		Claims: domainClaimsToProto(claims),
	}, nil
}

func domainClaimsToProto(c *domain.TokenClaims) *authv1.TokenClaims {
	return &authv1.TokenClaims{
		Subject:       c.Subject,
		Roles:         c.Roles,
		Scopes:        c.Scopes,
		ClientType:    string(c.ClientType),
		TokenId:       c.TokenID,
		ExpiresAt:     c.ExpiresAt.Unix(),
		IssuedAt:      c.IssuedAt.Unix(),
		JktThumbprint: c.JKTThumbprint,
	}
}

func domainUserToProto(u *domain.User) *authv1.User {
	return &authv1.User{
		Id:            u.ID,
		Email:         u.Email,
		Name:          u.Name,
		Roles:         u.Roles,
		Locked:        u.Locked,
		EmailVerified: u.EmailVerified,
		CreatedAt:     u.CreatedAt.Unix(),
		UpdatedAt:     u.UpdatedAt.Unix(),
	}
}
