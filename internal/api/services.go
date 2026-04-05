package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"
)

// AuthResult contains the tokens returned after successful authentication.
type AuthResult struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	UserID       string `json:"user_id,omitempty"`
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

// DPoPTokenService extends TokenService with DPoP-bound token issuance.
// token.Service implements this via the IssueTokenPairDPoP method.
type DPoPTokenService interface {
	// RefreshDPoP exchanges a refresh token for a new DPoP-bound token pair.
	RefreshDPoP(ctx context.Context, refreshToken, dpopThumbprint string) (*AuthResult, error)
	// ClientCredentialsDPoP issues a DPoP-bound token for service-to-service auth.
	ClientCredentialsDPoP(ctx context.Context, clientID, clientSecret, dpopThumbprint string) (*AuthResult, error)
}

// DPoPProofValidator defines the operations for DPoP proof validation at the handler level.
type DPoPProofValidator interface {
	// Enabled reports whether DPoP is active.
	Enabled() bool
	// ValidateProof validates a DPoP proof JWT.
	ValidateProof(ctx context.Context, proof, httpMethod, httpURI string) (thumbprint string, err error)
}

// SessionInfo represents a single user session returned by the API.
type SessionInfo struct {
	ID             string    `json:"id"`
	UserID         string    `json:"user_id"`
	IPAddress      string    `json:"ip_address"`
	UserAgent      string    `json:"user_agent"`
	CreatedAt      time.Time `json:"created_at"`
	LastActivityAt time.Time `json:"last_activity_at"`
	Current        bool      `json:"current"`
}

// SessionList is the response envelope for listing sessions.
type SessionList struct {
	Sessions []SessionInfo `json:"sessions"`
}

// SessionService defines the operations for session management.
type SessionService interface {
	CreateSession(ctx context.Context, userID, ipAddress, userAgent string) (*SessionInfo, error)
	ListSessions(ctx context.Context, userID string) ([]SessionInfo, error)
	DeleteSession(ctx context.Context, userID, sessionID string) error
	DeleteAllSessions(ctx context.Context, userID string) error
}

// Services aggregates all service interfaces required by the API handlers.
type Services struct {
	Auth          AuthService
	Token         TokenService
	DPoPToken     DPoPTokenService   // optional; nil when DPoP is disabled
	DPoPValidator DPoPProofValidator // optional; nil when DPoP is disabled
	Session       SessionService
}

// MiddlewareStack holds middleware handler functions used by the router.
// CORS is applied first at the engine level so preflight OPTIONS requests
// are handled before any other middleware rejects them.
type MiddlewareStack struct {
	CORS            gin.HandlerFunc
	CorrelationID   gin.HandlerFunc
	SecurityHeaders gin.HandlerFunc
	RateLimit       gin.HandlerFunc
	RequestSize     gin.HandlerFunc
	APIKey          gin.HandlerFunc
	Auth            gin.HandlerFunc
	DPoP            gin.HandlerFunc
	Metrics         gin.HandlerFunc
}
