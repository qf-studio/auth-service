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

// Client approval status constants.
const (
	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusRejected = "rejected"
)

// AuthorizationCode represents an OAuth2 authorization code stored as a hash.
type AuthorizationCode struct {
	ID                   uuid.UUID `json:"id"                       db:"id"`
	CodeHash             string    `json:"-"                        db:"code_hash"`
	ClientID             uuid.UUID `json:"client_id"                db:"client_id"`
	UserID               string    `json:"user_id"                  db:"user_id"`
	RedirectURI          string    `json:"redirect_uri"             db:"redirect_uri"`
	Scopes               []string  `json:"scopes"                   db:"scopes"`
	CodeChallenge        string    `json:"-"                        db:"code_challenge"`
	CodeChallengeMethod  string    `json:"-"                        db:"code_challenge_method"`
	Nonce                string    `json:"nonce,omitempty"          db:"nonce"`
	ExpiresAt            time.Time `json:"expires_at"               db:"expires_at"`
	UsedAt               *time.Time `json:"used_at,omitempty"       db:"used_at"`
	CreatedAt            time.Time `json:"created_at"               db:"created_at"`
}

// IsExpired returns true if the authorization code has expired.
func (ac *AuthorizationCode) IsExpired() bool {
	return time.Now().UTC().After(ac.ExpiresAt)
}

// IsUsed returns true if the authorization code has already been exchanged.
func (ac *AuthorizationCode) IsUsed() bool {
	return ac.UsedAt != nil
}

// ConsentSession represents an OIDC consent session tracking user authorization decisions.
type ConsentSession struct {
	ID               uuid.UUID    `json:"id"                       db:"id"`
	Challenge        string       `json:"challenge"                db:"challenge"`
	Verifier         string       `json:"-"                        db:"verifier"`
	ClientID         uuid.UUID    `json:"client_id"                db:"client_id"`
	UserID           string       `json:"user_id"                  db:"user_id"`
	RequestedScopes  []string     `json:"requested_scopes"         db:"requested_scopes"`
	GrantedScopes    []string     `json:"granted_scopes"           db:"granted_scopes"`
	State            ConsentState `json:"state"                    db:"state"`
	LoginSessionID   string       `json:"login_session_id"         db:"login_session_id"`
	EncryptedPayload []byte       `json:"-"                        db:"encrypted_payload"`
	CreatedAt        time.Time    `json:"created_at"               db:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at"               db:"updated_at"`
	ExpiresAt        *time.Time   `json:"expires_at,omitempty"     db:"expires_at"`
}

// IDTokenClaims holds the standard OIDC ID token claims.
type IDTokenClaims struct {
	Subject       string   `json:"sub"`
	Issuer        string   `json:"iss"`
	Audience      string   `json:"aud"`
	ExpiresAt     int64    `json:"exp"`
	IssuedAt      int64    `json:"iat"`
	AuthTime      int64    `json:"auth_time,omitempty"`
	Nonce         string   `json:"nonce,omitempty"`
	Email         string   `json:"email,omitempty"`
	EmailVerified bool     `json:"email_verified,omitempty"`
	Name          string   `json:"name,omitempty"`
	Scopes        []string `json:"-"`
}

// UserInfoResponse holds the OIDC UserInfo endpoint response fields.
type UserInfoResponse struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	EmailVerified bool   `json:"email_verified,omitempty"`
	Name          string `json:"name,omitempty"`
	UpdatedAt     int64  `json:"updated_at,omitempty"`
}
