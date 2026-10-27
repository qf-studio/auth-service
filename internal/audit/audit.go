// Package audit provides structured audit event logging for security-relevant
// operations. Events are dispatched asynchronously via a buffered channel,
// logged via zap and persisted in batches by a pluggable Sink.
package audit

import (
	"context"
	"time"

	"github.com/google/uuid"
)

// Event types for all auditable operations.
const (
	EventLoginSuccess             = "login_success"
	EventLoginFailure             = "login_failure"
	EventRegister                 = "register"
	EventRegisterDuplicate        = "register_duplicate"
	EventLogout                   = "logout"
	EventLogoutAll                = "logout_all"
	EventPasswordChange           = "password_change"
	EventProfileUpdated           = "profile_updated"
	EventPasswordReset            = "password_reset"
	EventPasswordResetConfm       = "password_reset_confirm"
	EventPasswordResetEmailFailed = "password_reset_email_failed"
	EventEmailVerifyEmailFailed   = "email_verify_email_failed"
	EventEmailVerified            = "email_verified"
	EventEmailChangeRequested     = "email_change_requested"
	EventEmailChanged             = "email_changed"
	EventEmailChangeReverted      = "email_change_reverted"
	EventEmailChangeEmailFailed   = "email_change_email_failed"
	EventPasswordExpired          = "password_expired"
	EventHashUpgraded             = "hash_upgraded"
	EventPasswordReused           = "password_reused"
	EventPasswordBreached         = "password_breached"
	EventBreachCheckFailed        = "password_breach_check_failed"
	EventTokenRefresh             = "token_refresh"
	EventTokenRevoke              = "token_revoke"
	EventAdminUserCreate          = "admin_user_create"
	EventAdminUserUpdate          = "admin_user_update"
	EventAdminUserDelete          = "admin_user_delete"
	EventAdminUserLock            = "admin_user_lock"
	EventAdminUserUnlock          = "admin_user_unlock"
	EventAdminClientCreate        = "admin_client_create"
	EventAdminClientUpdate        = "admin_client_update"
	EventAdminClientDelete        = "admin_client_delete"
	EventAdminClientRotate        = "admin_client_rotate_secret"
	EventTokenIntrospect          = "token_introspect"
	EventAdminAPIKeyCreate        = "admin_apikey_create"
	EventAdminAPIKeyUpdate        = "admin_apikey_update"
	EventAdminAPIKeyRevoke        = "admin_apikey_revoke"
	EventAdminAPIKeyRotate        = "admin_apikey_rotate"
	EventAdminWebhookCreate       = "admin_webhook_create"
	EventAdminWebhookUpdate       = "admin_webhook_update"
	EventAdminWebhookDelete       = "admin_webhook_delete"
	EventAdminWebhookTest         = "admin_webhook_test"
	EventAdminWebhookRetry        = "admin_webhook_retry"

	// Broker credential events.
	EventAdminBrokerCredentialCreate = "admin_broker_credential_create"
	EventAdminBrokerCredentialUpdate = "admin_broker_credential_update"
	EventAdminBrokerCredentialDelete = "admin_broker_credential_delete"
	EventAdminBrokerCredentialRotate = "admin_broker_credential_rotate"
	EventBrokerTokenIssue            = "broker_token_issue"
	EventBrokerTokenDenied           = "broker_token_denied"

	// Tenant events.
	EventAdminTenantCreate = "admin_tenant_create"
	EventAdminTenantUpdate = "admin_tenant_update"
	EventAdminTenantDelete = "admin_tenant_delete"

	// SAML events.
	EventSAMLLogin            = "saml_login"
	EventSAMLLoginFailure     = "saml_login_failure"
	EventSAMLJITProvision     = "saml_jit_provision"
	EventAdminSAMLIdPCreate   = "admin_saml_idp_create"
	EventAdminSAMLIdPUpdate   = "admin_saml_idp_update"
	EventAdminSAMLIdPDelete   = "admin_saml_idp_delete"
	EventAdminSAMLIdPMetadata = "admin_saml_idp_metadata_import"
	EventAdminSAMLAttrMap     = "admin_saml_attribute_mapping"

	// OIDC provider events.
	EventOIDCCodeExchange   = "oidc_code_exchange"
	EventOIDCCodeReuse      = "oidc_code_reuse"
	EventOIDCConsentGrant   = "oidc_consent_grant"
	EventOIDCConsentReject  = "oidc_consent_reject"
	EventOIDCLoginAccept    = "oidc_login_accept"
	EventOIDCLoginReject    = "oidc_login_reject"
	EventAdminClientApprove = "admin_client_approve"
)

// Event represents a single audit log entry.
type Event struct {
	TenantID  uuid.UUID // zero value: resolved from the LogEvent context
	Type      string
	ActorID   string // user or client performing the action
	TargetID  string // resource being acted upon
	IP        string
	UserAgent string
	Metadata  map[string]string
	Timestamp time.Time
}

// EventLogger is the interface consumed by services to emit audit events.
type EventLogger interface {
	LogEvent(ctx context.Context, event Event)
}

// NopLogger is a no-op implementation of EventLogger for use in tests.
type NopLogger struct{}

// LogEvent does nothing.
func (NopLogger) LogEvent(_ context.Context, _ Event) {}
