package domain

import (
	"time"

	"github.com/google/uuid"
)

// ConsentGrant represents a durable record that a user has approved a client
// to access a given set of scopes. It backs the "remember my consent" flow
// for the OIDC login/consent screens: when a grant exists and covers the
// scopes an authorization request asks for, the consent screen can be
// skipped on subsequent authorizations.
type ConsentGrant struct {
	ID        uuid.UUID  `json:"id"`
	TenantID  uuid.UUID  `json:"tenant_id"`
	UserID    string     `json:"user_id"`
	ClientID  uuid.UUID  `json:"client_id"`
	Scopes    []string   `json:"scopes"`
	GrantedAt time.Time  `json:"granted_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// IsActive reports whether the grant has not been revoked.
func (g *ConsentGrant) IsActive() bool {
	return g.RevokedAt == nil
}

// CoversScopes reports whether the grant's approved scopes are a superset of
// the requested scopes.
func (g *ConsentGrant) CoversScopes(requested []string) bool {
	granted := make(map[string]struct{}, len(g.Scopes))
	for _, s := range g.Scopes {
		granted[s] = struct{}{}
	}
	for _, s := range requested {
		if _, ok := granted[s]; !ok {
			return false
		}
	}
	return true
}
