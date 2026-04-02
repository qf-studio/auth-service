package api

import (
	"context"

	"github.com/gin-gonic/gin"
)

// AuthResult contains the tokens returned after successful authentication.
type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// UserInfo represents the authenticated user's profile.
type UserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// JWKSResponse represents the JSON Web Key Set returned by the JWKS endpoint.
type JWKSResponse struct {
	Keys []interface{} `json:"keys"`
}

// AuthService defines the operations for authentication and user management.
type AuthService interface {
	Register(ctx context.Context, email, password, name string) (*UserInfo, error)
	Login(ctx context.Context, email, password string) (*AuthResult, error)
	ResetPassword(ctx context.Context, email string) error
	ConfirmPasswordReset(ctx context.Context, token, newPassword string) error
	GetMe(ctx context.Context, userID string) (*UserInfo, error)
	ChangePassword(ctx context.Context, userID, oldPassword, newPassword string) error
	Logout(ctx context.Context, userID, token string) error
	LogoutAll(ctx context.Context, userID string) error
}

// TokenService defines the operations for token management.
type TokenService interface {
	Refresh(ctx context.Context, refreshToken string) (*AuthResult, error)
	ClientCredentials(ctx context.Context, clientID, clientSecret string) (*AuthResult, error)
	Revoke(ctx context.Context, token string) error
	JWKS(ctx context.Context) (*JWKSResponse, error)
}

// Services aggregates all service interfaces required by the API handlers.
type Services struct {
	Auth  AuthService
	Token TokenService
}

// MiddlewareStack holds middleware handler functions used by the router.
type MiddlewareStack struct {
	CorrelationID gin.HandlerFunc
	SecurityHeaders gin.HandlerFunc
	RateLimit     gin.HandlerFunc
	RequestSize   gin.HandlerFunc
	Auth          gin.HandlerFunc
}
