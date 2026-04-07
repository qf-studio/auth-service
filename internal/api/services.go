package api

import (
	"context"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/qf-studio/auth-service/internal/domain"
)

// AuthResult contains the tokens returned after successful authentication.
// When MFA is required, only MFARequired and MFAToken are populated.
// When ForcePasswordChange is true, the client must change password before proceeding.
type AuthResult struct {
	AccessToken         string `json:"access_token,omitempty"`
	RefreshToken        string `json:"refresh_token,omitempty"`
	TokenType           string `json:"token_type,omitempty"`
	ExpiresIn           int    `json:"expires_in,omitempty"`
	UserID              string `json:"user_id,omitempty"`
	MFARequired         bool   `json:"mfa_required,omitempty"`
	MFAToken            string `json:"mfa_token,omitempty"`
	ForcePasswordChange bool   `json:"force_password_change,omitempty"`
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
	RefreshWithDPoP(ctx context.Context, refreshToken, jktThumbprint string) (*AuthResult, error)
	ClientCredentials(ctx context.Context, clientID, clientSecret string) (*AuthResult, error)
	ClientCredentialsWithDPoP(ctx context.Context, clientID, clientSecret, jktThumbprint string) (*AuthResult, error)
	Revoke(ctx context.Context, token string) error
	JWKS(ctx context.Context) (*JWKSResponse, error)
}

// DPoPProofClaims contains validated claims from a DPoP proof JWT.
type DPoPProofClaims struct {
	JKTThumbprint string
	HTTPMethod    string
	HTTPURI       string
}

// DPoPService defines the operations for DPoP proof validation.
type DPoPService interface {
	Enabled() bool
	ValidateProof(ctx context.Context, proofJWT, httpMethod, httpURI string) (*DPoPProofClaims, error)
	IssueNonce(ctx context.Context) (string, error)
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

// MFAEnrollmentResult is returned when a user initiates MFA enrollment.
type MFAEnrollmentResult struct {
	Secret string `json:"secret"`
	URI    string `json:"uri"`
}

// MFAConfirmResult is returned when enrollment is confirmed, containing backup codes.
type MFAConfirmResult struct {
	BackupCodes []string `json:"backup_codes"`
}

// MFAStatusResponse is returned by the MFA status endpoint.
type MFAStatusResponse struct {
	Enabled    bool   `json:"enabled"`
	Type       string `json:"type,omitempty"`
	Confirmed  bool   `json:"confirmed"`
	BackupLeft int    `json:"backup_codes_remaining"`
}

// MFAService defines the operations for multi-factor authentication.
type MFAService interface {
	InitiateEnrollment(ctx context.Context, userID, email string) (*MFAEnrollmentResult, error)
	ConfirmEnrollment(ctx context.Context, userID, code string) ([]string, error)
	VerifyTOTP(ctx context.Context, userID, code string) error
	VerifyBackupCode(ctx context.Context, userID, code string) error
	CompleteMFALogin(ctx context.Context, mfaToken, code, codeType string) (*AuthResult, error)
	Disable(ctx context.Context, userID string) error
	GetStatus(ctx context.Context, userID string) (*MFAStatusResponse, error)
	IsMFAEnabled(ctx context.Context, userID string) (bool, error)
	GenerateMFAToken(ctx context.Context, userID string) (string, error)
}

// OAuthService defines the operations for OAuth social login and account linking.
type OAuthService interface {
	GetAuthURL(ctx context.Context, provider string) (*domain.OAuthAuthURL, error)
	HandleCallback(ctx context.Context, provider, code, state string) (*AuthResult, error)
	ListLinkedAccounts(ctx context.Context, userID string) (*domain.OAuthLinkedAccounts, error)
	UnlinkAccount(ctx context.Context, userID, provider string) error
}

// --- OIDC Provider types ---

// OIDCDiscoveryResponse is the OpenID Connect discovery document (RFC 8414).
type OIDCDiscoveryResponse struct {
	Issuer                           string   `json:"issuer"`
	AuthorizationEndpoint            string   `json:"authorization_endpoint"`
	TokenEndpoint                    string   `json:"token_endpoint"`
	UserinfoEndpoint                 string   `json:"userinfo_endpoint"`
	JwksURI                          string   `json:"jwks_uri"`
	ScopesSupported                  []string `json:"scopes_supported"`
	ResponseTypesSupported           []string `json:"response_types_supported"`
	GrantTypesSupported              []string `json:"grant_types_supported"`
	SubjectTypesSupported            []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported    []string `json:"code_challenge_methods_supported"`
}

// AuthorizeRequest represents the parameters for an OAuth2 authorization request.
type AuthorizeRequest struct {
	ClientID            string `form:"client_id"             binding:"required"`
	RedirectURI         string `form:"redirect_uri"          binding:"required"`
	ResponseType        string `form:"response_type"         binding:"required"`
	Scope               string `form:"scope"                 binding:"required"`
	State               string `form:"state"`
	Nonce               string `form:"nonce"`
	CodeChallenge       string `form:"code_challenge"`
	CodeChallengeMethod string `form:"code_challenge_method"`
}

// AuthorizeResponse is returned by the authorization endpoint.
type AuthorizeResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// CodeExchangeRequest represents the token request for authorization_code grant.
type CodeExchangeRequest struct {
	GrantType    string `json:"grant_type"    binding:"required"`
	Code         string `json:"code"          binding:"required"`
	RedirectURI  string `json:"redirect_uri"  binding:"required"`
	ClientID     string `json:"client_id"     binding:"required"`
	ClientSecret string `json:"client_secret"`
	CodeVerifier string `json:"code_verifier"`
}

// OIDCTokenResponse is the token response including an optional ID token.
type OIDCTokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// OIDCUserInfoResponse represents the UserInfo endpoint response (OIDC Core §5.3).
type OIDCUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
}

// OIDCProviderService defines operations for the OIDC provider (authorization server).
type OIDCProviderService interface {
	// GetDiscovery returns the OpenID Connect discovery document.
	GetDiscovery(ctx context.Context) (*OIDCDiscoveryResponse, error)
	// Authorize initiates the authorization code flow and returns a redirect URL.
	Authorize(ctx context.Context, req *AuthorizeRequest) (*AuthorizeResponse, error)
	// ExchangeCode exchanges an authorization code for tokens.
	ExchangeCode(ctx context.Context, req *CodeExchangeRequest) (*OIDCTokenResponse, error)
	// GetUserInfo returns claims about the authenticated user.
	GetUserInfo(ctx context.Context, userID string) (*OIDCUserInfoResponse, error)
}

// --- Consent flow types ---

// LoginRequestInfo describes a pending login request shown to the consent UI.
type LoginRequestInfo struct {
	Challenge string `json:"challenge"`
	ClientID  string `json:"client_id"`
	Scope     string `json:"scope"`
	RequestURL string `json:"request_url"`
}

// AcceptLoginRequest is the body for accepting a login request.
type AcceptLoginRequest struct {
	Subject  string `json:"subject"  binding:"required"`
	Remember bool   `json:"remember"`
}

// ConsentRequestInfo describes a pending consent request shown to the consent UI.
type ConsentRequestInfo struct {
	Challenge       string   `json:"challenge"`
	ClientID        string   `json:"client_id"`
	RequestedScopes []string `json:"requested_scopes"`
	Subject         string   `json:"subject"`
}

// AcceptConsentRequest is the body for accepting a consent request.
type AcceptConsentRequest struct {
	GrantedScopes []string `json:"granted_scopes" binding:"required"`
	Remember      bool     `json:"remember"`
}

// RejectRequest is the body for rejecting a login or consent request.
type RejectRequest struct {
	Error            string `json:"error"             binding:"required"`
	ErrorDescription string `json:"error_description"`
}

// RedirectResponse contains the URL to redirect to after a consent decision.
type RedirectResponse struct {
	RedirectTo string `json:"redirect_to"`
}

// ConsentService defines the admin-side operations for the login/consent flow.
type ConsentService interface {
	GetLoginRequest(ctx context.Context, challenge string) (*LoginRequestInfo, error)
	AcceptLogin(ctx context.Context, challenge string, req *AcceptLoginRequest) (*RedirectResponse, error)
	RejectLogin(ctx context.Context, challenge string, req *RejectRequest) (*RedirectResponse, error)
	GetConsentRequest(ctx context.Context, challenge string) (*ConsentRequestInfo, error)
	AcceptConsent(ctx context.Context, challenge string, req *AcceptConsentRequest) (*RedirectResponse, error)
	RejectConsent(ctx context.Context, challenge string, req *RejectRequest) (*RedirectResponse, error)
}

// ClientApprovalInfo represents the approval status of a third-party client.
type ClientApprovalInfo struct {
	ClientID   string `json:"client_id"`
	ClientName string `json:"client_name"`
	Approved   bool   `json:"approved"`
	ApprovedAt *time.Time `json:"approved_at,omitempty"`
	ApprovedBy string     `json:"approved_by,omitempty"`
}

// AdminClientApprovalService defines admin operations for third-party client approval.
type AdminClientApprovalService interface {
	CreateThirdPartyClient(ctx context.Context, req *CreateClientRequest) (*AdminClientWithSecret, error)
	ApproveClient(ctx context.Context, clientID string) (*ClientApprovalInfo, error)
}

// --- SAML types ---

// SAMLMetadataResponse contains the SP metadata XML.
type SAMLMetadataResponse struct {
	XML []byte
}

// SAMLLoginRequest contains the parameters for initiating SAML SSO.
type SAMLLoginRequest struct {
	IdPID       string `form:"idp_id"       binding:"required"`
	RelayState  string `form:"relay_state"`
}

// SAMLLoginResult contains the redirect URL to the IdP.
type SAMLLoginResult struct {
	RedirectURL string `json:"redirect_url"`
}

// SAMLACSResult contains the tokens issued after successful SAML assertion processing.
type SAMLACSResult struct {
	AccessToken    string `json:"access_token"`
	RefreshToken   string `json:"refresh_token"`
	TokenType      string `json:"token_type"`
	ExpiresIn      int    `json:"expires_in"`
	UserID         string `json:"user_id"`
	JITProvisioned bool   `json:"jit_provisioned,omitempty"`
}

// SAMLService defines the operations for SAML SSO authentication.
type SAMLService interface {
	// GetMetadata returns the SP metadata XML for the given IdP (or default).
	GetMetadata(ctx context.Context, idpID string) (*SAMLMetadataResponse, error)
	// InitiateSSO creates an AuthnRequest and returns the IdP redirect URL.
	InitiateSSO(ctx context.Context, idpID, relayState string) (*SAMLLoginResult, error)
	// ProcessResponse validates the SAML response and issues tokens.
	ProcessResponse(ctx context.Context, samlResponse, relayState string) (*SAMLACSResult, error)
}

// --- Broker token types ---

// BrokerTokenRequest is the request body for the public broker token endpoint.
type BrokerTokenRequest struct {
	ClientID     string `json:"client_id"     binding:"required"`
	ClientSecret string `json:"client_secret" binding:"required"`
	TargetName   string `json:"target_name"   binding:"required"`
}

// BrokerTokenResponse is returned when a broker token is successfully issued.
type BrokerTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	TargetName  string `json:"target_name"`
}

// BrokerTokenService defines the public-facing broker token issuance operation.
type BrokerTokenService interface {
	IssueBrokerToken(ctx context.Context, clientID, clientSecret, targetName string) (*BrokerTokenResponse, error)
}

// Services aggregates all service interfaces required by the API handlers.
type Services struct {
	Auth    AuthService
	Token   TokenService
	Session SessionService
	DPoP    DPoPService
	MFA     MFAService
	OAuth   OAuthService
	OIDC    OIDCProviderService
	Broker  BrokerTokenService
	SAML    SAMLService
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
	Tenant          gin.HandlerFunc
	APIKey          gin.HandlerFunc
	Auth            gin.HandlerFunc
	DPoP            gin.HandlerFunc
	Metrics         gin.HandlerFunc
}
