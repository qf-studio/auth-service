package domain

import (
	"time"

	"github.com/google/uuid"
)

// Tenant status constants.
const (
	TenantStatusActive   = "active"
	TenantStatusInactive = "inactive"
)

// Tenant represents a tenant in the multi-tenant auth system.
// Each tenant has its own isolated set of users, clients, and configuration.
type Tenant struct {
	ID     uuid.UUID `json:"id"     db:"id"`
	Slug   string    `json:"slug"   db:"slug"`
	Name   string    `json:"name"   db:"name"`
	Active bool      `json:"active" db:"active"`

	// Per-tenant password policy overrides (nil = use system defaults).
	PasswordMinLength    *int `json:"password_min_length,omitempty"    db:"password_min_length"`
	PasswordMaxLength    *int `json:"password_max_length,omitempty"    db:"password_max_length"`
	PasswordMaxAgeDays   *int `json:"password_max_age_days,omitempty"  db:"password_max_age_days"`
	PasswordHistoryCount *int `json:"password_history_count,omitempty" db:"password_history_count"`

	// MFA enforcement for the tenant.
	MFAEnforced bool `json:"mfa_enforced" db:"mfa_enforced"`

	// Allowed OAuth providers (nil = all allowed).
	AllowedOAuthProviders []string `json:"allowed_oauth_providers,omitempty" db:"allowed_oauth_providers"`

	// Custom token TTLs in seconds (nil = use system defaults).
	AccessTokenTTL  *int `json:"access_token_ttl,omitempty"  db:"access_token_ttl"`
	RefreshTokenTTL *int `json:"refresh_token_ttl,omitempty" db:"refresh_token_ttl"`

	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if the tenant is active.
func (t *Tenant) IsActive() bool {
	return t.Active
}

// EffectivePasswordPolicy returns the tenant's password policy, falling back
// to the provided system defaults for any fields not overridden.
func (t *Tenant) EffectivePasswordPolicy(defaults PasswordPolicy) PasswordPolicy {
	p := defaults
	if t.PasswordMinLength != nil {
		p.MinLength = *t.PasswordMinLength
	}
	if t.PasswordMaxLength != nil {
		p.MaxLength = *t.PasswordMaxLength
	}
	if t.PasswordMaxAgeDays != nil {
		p.MaxAgeDays = *t.PasswordMaxAgeDays
	}
	if t.PasswordHistoryCount != nil {
		p.HistoryCount = *t.PasswordHistoryCount
	}
	return p
}
