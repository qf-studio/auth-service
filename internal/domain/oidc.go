package domain

import (
	"time"

	"github.com/google/uuid"
)

// ConsentState represents the lifecycle state of a consent session.
type ConsentState string

const (
	ConsentStatePending  ConsentState = "pending"
	ConsentStateAccepted ConsentState = "accepted"
	ConsentStateRejected ConsentState = "rejected"
	ConsentStateRevoked  ConsentState = "revoked"
)

// IsValid returns true if the ConsentState is a recognised value.
func (cs ConsentState) IsValid() bool {
	switch cs {
	case ConsentStatePending, ConsentStateAccepted, ConsentStateRejected, ConsentStateRevoked:
		return true
	}
	return false
}

// Client approval status constants for third-party clients.
const (
	ClientApprovalPending  = "pending"
	ClientApprovalApproved = "approved"
	ClientApprovalRejected = "rejected"
)

// AuthorizationCode represents an OAuth2 authorization code stored in the database.
// The actual code is never persisted — only its hash (code_hash) is stored.
type AuthorizationCode struct {
	ID                  uuid.UUID  `json:"id"                    db:"id"`
	CodeHash            string     `json:"-"                     db:"code_hash"`
	ClientID            uuid.UUID  `json:"client_id"             db:"client_id"`
	UserID              string     `json:"user_id"               db:"user_id"`
	RedirectURI         string     `json:"redirect_uri"          db:"redirect_uri"`
	Scopes              []string   `json:"scopes"                db:"scopes"`
	CodeChallenge       string     `json:"-"                     db:"code_challenge"`
	CodeChallengeMethod string     `json:"-"                     db:"code_challenge_method"`
	Nonce               string     `json:"-"                     db:"nonce"`
	ExpiresAt           time.Time  `json:"expires_at"            db:"expires_at"`
	UsedAt              *time.Time `json:"used_at,omitempty"     db:"used_at"`
	CreatedAt           time.Time  `json:"created_at"            db:"created_at"`
}

// IsExpired returns true if the authorization code has passed its expiration time.
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().After(ac.ExpiresAt)
}

// IsUsed returns true if the authorization code has already been consumed.
func (ac *AuthorizationCode) IsUsed() bool {
	return ac.UsedAt != nil
}

// ConsentSession tracks a user's consent decision for a specific client and scope set.
type ConsentSession struct {
	ID               uuid.UUID    `json:"id"                db:"id"`
	Challenge        string       `json:"challenge"         db:"challenge"`
	Verifier         string       `json:"-"                 db:"verifier"`
	ClientID         uuid.UUID    `json:"client_id"         db:"client_id"`
	UserID           string       `json:"user_id"           db:"user_id"`
	RequestedScopes  []string     `json:"requested_scopes"  db:"requested_scopes"`
	GrantedScopes    []string     `json:"granted_scopes"    db:"granted_scopes"`
	State            ConsentState `json:"state"             db:"state"`
	LoginSessionID   string       `json:"login_session_id"  db:"login_session_id"`
	EncryptedPayload []byte       `json:"-"                 db:"encrypted_payload"`
	CreatedAt        time.Time    `json:"created_at"        db:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"        db:"updated_at"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty" db:"expires_at"`
}

// IDTokenClaims holds the standard OIDC ID Token claims.
type IDTokenClaims struct {
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	IssuedAt  int64    `json:"iat"`
	AuthTime  int64    `json:"auth_time,omitempty"`
	Nonce     string   `json:"nonce,omitempty"`
	Email     string   `json:"email,omitempty"`
	Name      string   `json:"name,omitempty"`
}

// UserInfoResponse represents the OIDC UserInfo endpoint response.
type UserInfoResponse struct {
	Subject string `json:"sub"`
	Email   string `json:"email,omitempty"`
	Name    string `json:"name,omitempty"`
}
