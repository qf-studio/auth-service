package api

import (
	"context"
	"time"
)

// --- Admin response types ---

// AdminUser represents a user record in admin API responses.
type AdminUser struct {
	ID           string     `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	Roles        []string   `json:"roles"`
	Locked       bool       `json:"locked"`
	LockedAt     *time.Time `json:"locked_at,omitempty"`
	LockedReason string     `json:"locked_reason,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// AdminUserList is the paginated response for listing users.
type AdminUserList struct {
	Users   []AdminUser `json:"users"`
	Total   int         `json:"total"`
	Page    int         `json:"page"`
	PerPage int         `json:"per_page"`
}

// AdminClient represents an OAuth2 client in admin API responses.
type AdminClient struct {
	ID           string     `json:"id"`
	Name         string     `json:"name"`
	ClientType   string     `json:"client_type"`
	Scopes       []string   `json:"scopes"`
	RedirectURIs []string   `json:"redirect_uris,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	DeletedAt    *time.Time `json:"deleted_at,omitempty"`
}

// AdminClientWithSecret is returned only on create and secret rotation.
type AdminClientWithSecret struct {
	AdminClient
	ClientSecret    string     `json:"client_secret"`
	GracePeriodEnds *time.Time `json:"grace_period_ends,omitempty"`
}

// AdminClientList is the paginated response for listing clients.
type AdminClientList struct {
	Clients []AdminClient `json:"clients"`
	Total   int           `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

// AdminAPIKey represents an API key in admin API responses.
type AdminAPIKey struct {
	ID         string     `json:"id"`
	ClientID   string     `json:"client_id"`
	Name       string     `json:"name"`
	KeyPrefix  string     `json:"key_prefix"`
	Scopes     []string   `json:"scopes"`
	RateLimit  int        `json:"rate_limit"`
	Status     string     `json:"status"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
}

// AdminAPIKeyWithSecret is returned only on create and key rotation.
type AdminAPIKeyWithSecret struct {
	AdminAPIKey
	Key             string     `json:"key"`
	GracePeriodEnds *time.Time `json:"grace_period_ends,omitempty"`
}

// AdminAPIKeyList is the paginated response for listing API keys.
type AdminAPIKeyList struct {
	APIKeys []AdminAPIKey `json:"api_keys"`
	Total   int           `json:"total"`
	Page    int           `json:"page"`
	PerPage int           `json:"per_page"`
}

// IntrospectionResponse follows RFC 7662 token introspection.
type IntrospectionResponse struct {
	Active     bool   `json:"active"`
	Sub        string `json:"sub,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
	Scope      string `json:"scope,omitempty"`
	Exp        int64  `json:"exp,omitempty"`
	Iat        int64  `json:"iat,omitempty"`
	Iss        string `json:"iss,omitempty"`
	Jti        string `json:"jti,omitempty"`
	ClientType string `json:"client_type,omitempty"`
}

// --- Admin request types ---

// CreateUserRequest is the request body for creating a user via admin API.
type CreateUserRequest struct {
	Email    string   `json:"email"    validate:"required,email"`
	Password string   `json:"password" validate:"required,min=15"`
	Name     string   `json:"name"     validate:"required,min=1,max=255"`
	Roles    []string `json:"roles"    validate:"omitempty"`
}

// UpdateUserRequest is the request body for updating a user via admin API.
type UpdateUserRequest struct {
	Email *string  `json:"email" validate:"omitempty,email"`
	Name  *string  `json:"name"  validate:"omitempty,min=1,max=255"`
	Roles []string `json:"roles" validate:"omitempty"`
}

// LockUserRequest is the request body for locking a user account.
type LockUserRequest struct {
	Reason string `json:"reason" validate:"required,min=1,max=500"`
}

// CreateClientRequest is the request body for creating an OAuth2 client.
type CreateClientRequest struct {
	Name         string   `json:"name"          validate:"required,min=1,max=255"`
	ClientType   string   `json:"client_type"   validate:"required,oneof=service agent"`
	Scopes       []string `json:"scopes"        validate:"omitempty"`
	RedirectURIs []string `json:"redirect_uris" validate:"omitempty"`
}

// UpdateClientRequest is the request body for updating an OAuth2 client.
type UpdateClientRequest struct {
	Name         *string  `json:"name"          validate:"omitempty,min=1,max=255"`
	Scopes       []string `json:"scopes"        validate:"omitempty"`
	RedirectURIs []string `json:"redirect_uris" validate:"omitempty"`
}

// IntrospectRequest is the request body for RFC 7662 token introspection.
type IntrospectRequest struct {
	Token string `json:"token" validate:"required"`
}

// CreateAPIKeyRequest is the request body for creating an API key.
type CreateAPIKeyRequest struct {
	ClientID  string   `json:"client_id"  validate:"required,uuid"`
	Name      string   `json:"name"       validate:"required,min=1,max=255"`
	Scopes    []string `json:"scopes"     validate:"omitempty"`
	RateLimit *int     `json:"rate_limit" validate:"omitempty,min=0,max=100000"`
	ExpiresAt *string  `json:"expires_at" validate:"omitempty"`
}

// UpdateAPIKeyRequest is the request body for updating an API key.
type UpdateAPIKeyRequest struct {
	Name      *string  `json:"name"       validate:"omitempty,min=1,max=255"`
	Scopes    []string `json:"scopes"     validate:"omitempty"`
	RateLimit *int     `json:"rate_limit" validate:"omitempty,min=0,max=100000"`
}

// --- Admin service interfaces ---

// AdminUserService defines admin operations for user management.
type AdminUserService interface {
	ListUsers(ctx context.Context, page, perPage int, status string) (*AdminUserList, error)
	GetUser(ctx context.Context, userID string) (*AdminUser, error)
	CreateUser(ctx context.Context, req *CreateUserRequest) (*AdminUser, error)
	UpdateUser(ctx context.Context, userID string, req *UpdateUserRequest) (*AdminUser, error)
	DeleteUser(ctx context.Context, userID string) error
	LockUser(ctx context.Context, userID string, reason string) (*AdminUser, error)
	UnlockUser(ctx context.Context, userID string) (*AdminUser, error)
}

// AdminClientService defines admin operations for OAuth2 client management.
type AdminClientService interface {
	ListClients(ctx context.Context, page, perPage int, clientType string, includeRevoked bool) (*AdminClientList, error)
	GetClient(ctx context.Context, clientID string) (*AdminClient, error)
	CreateClient(ctx context.Context, req *CreateClientRequest) (*AdminClientWithSecret, error)
	UpdateClient(ctx context.Context, clientID string, req *UpdateClientRequest) (*AdminClient, error)
	DeleteClient(ctx context.Context, clientID string) error
	RotateSecret(ctx context.Context, clientID string) (*AdminClientWithSecret, error)
}

// AdminTokenService defines admin operations for token introspection.
type AdminTokenService interface {
	Introspect(ctx context.Context, token string) (*IntrospectionResponse, error)
}

// AdminAPIKeyService defines admin operations for API key management.
type AdminAPIKeyService interface {
	ListAPIKeys(ctx context.Context, page, perPage int, clientID string) (*AdminAPIKeyList, error)
	GetAPIKey(ctx context.Context, keyID string) (*AdminAPIKey, error)
	CreateAPIKey(ctx context.Context, req *CreateAPIKeyRequest) (*AdminAPIKeyWithSecret, error)
	UpdateAPIKey(ctx context.Context, keyID string, req *UpdateAPIKeyRequest) (*AdminAPIKey, error)
	RevokeAPIKey(ctx context.Context, keyID string) error
	RotateAPIKey(ctx context.Context, keyID string) (*AdminAPIKeyWithSecret, error)
}

// --- Webhook admin types ---

// AdminWebhook represents a webhook subscription in admin API responses.
type AdminWebhook struct {
	ID           string    `json:"id"`
	URL          string    `json:"url"`
	EventTypes   []string  `json:"event_types"`
	Active       bool      `json:"active"`
	FailureCount int       `json:"failure_count"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AdminWebhookWithSecret is returned only on create (includes the raw signing secret).
type AdminWebhookWithSecret struct {
	AdminWebhook
	Secret string `json:"secret"`
}

// AdminWebhookList is the paginated response for listing webhooks.
type AdminWebhookList struct {
	Webhooks []AdminWebhook `json:"webhooks"`
	Total    int            `json:"total"`
	Page     int            `json:"page"`
	PerPage  int            `json:"per_page"`
}

// AdminWebhookDelivery represents a webhook delivery log entry.
type AdminWebhookDelivery struct {
	ID           string     `json:"id"`
	WebhookID    string     `json:"webhook_id"`
	EventType    string     `json:"event_type"`
	Payload      string     `json:"payload"`
	Status       string     `json:"status"`
	ResponseCode *int       `json:"response_code,omitempty"`
	ResponseBody *string    `json:"response_body,omitempty"`
	Attempt      int        `json:"attempt"`
	NextRetryAt  *time.Time `json:"next_retry_at,omitempty"`
	DeliveredAt  *time.Time `json:"delivered_at,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
}

// AdminWebhookDeliveryList is the paginated response for listing deliveries.
type AdminWebhookDeliveryList struct {
	Deliveries []AdminWebhookDelivery `json:"deliveries"`
	Total      int                    `json:"total"`
	Page       int                    `json:"page"`
	PerPage    int                    `json:"per_page"`
}

// CreateWebhookRequest is the request body for creating a webhook.
type CreateWebhookRequest struct {
	URL        string   `json:"url"         validate:"required,url"`
	EventTypes []string `json:"event_types" validate:"required,min=1"`
}

// UpdateWebhookRequest is the request body for updating a webhook.
type UpdateWebhookRequest struct {
	URL        *string  `json:"url"         validate:"omitempty,url"`
	EventTypes []string `json:"event_types" validate:"omitempty"`
	Active     *bool    `json:"active"      validate:"omitempty"`
}

// TestWebhookRequest is the request body for sending a test webhook event.
type TestWebhookRequest struct {
	EventType string `json:"event_type" validate:"required"`
}

// TestWebhookResponse is the response for a test webhook delivery.
type TestWebhookResponse struct {
	DeliveryID   string `json:"delivery_id"`
	Status       string `json:"status"`
	ResponseCode *int   `json:"response_code,omitempty"`
}

// AdminWebhookService defines admin operations for webhook management.
type AdminWebhookService interface {
	ListWebhooks(ctx context.Context, page, perPage int, activeOnly bool) (*AdminWebhookList, error)
	GetWebhook(ctx context.Context, webhookID string) (*AdminWebhook, error)
	CreateWebhook(ctx context.Context, req *CreateWebhookRequest) (*AdminWebhookWithSecret, error)
	UpdateWebhook(ctx context.Context, webhookID string, req *UpdateWebhookRequest) (*AdminWebhook, error)
	DeleteWebhook(ctx context.Context, webhookID string) error
	ListDeliveries(ctx context.Context, webhookID string, page, perPage int) (*AdminWebhookDeliveryList, error)
	RetryDelivery(ctx context.Context, webhookID, deliveryID string) (*AdminWebhookDelivery, error)
	TestWebhook(ctx context.Context, webhookID string, req *TestWebhookRequest) (*TestWebhookResponse, error)
}

// AdminServices aggregates all admin service interfaces required by admin API handlers.
type AdminServices struct {
	Users          AdminUserService
	Clients        AdminClientService
	Tokens         AdminTokenService
	APIKeys        AdminAPIKeyService
	MFA            MFAService
	Consent        ConsentService
	ClientApproval AdminClientApprovalService
	Webhooks       AdminWebhookService
}
