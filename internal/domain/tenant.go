package domain

import (
	"time"

	"github.com/google/uuid"
)

// TenantStatus represents the lifecycle state of a tenant.
type TenantStatus string

const (
	TenantStatusActive    TenantStatus = "active"
	TenantStatusSuspended TenantStatus = "suspended"
	TenantStatusDeleted   TenantStatus = "deleted"
)

// IsValid returns true if the TenantStatus is a recognised value.
func (ts TenantStatus) IsValid() bool {
	switch ts {
	case TenantStatusActive, TenantStatusSuspended, TenantStatusDeleted:
		return true
	}
	return false
}

// DefaultTenantID is the UUID of the seed tenant created by migration 000012.
var DefaultTenantID = uuid.MustParse("00000000-0000-0000-0000-000000000001")

// Tenant represents an isolated tenant in the multi-tenant auth service.
type Tenant struct {
	ID        uuid.UUID    `json:"id"         db:"id"`
	Name      string       `json:"name"       db:"name"`
	Slug      string       `json:"slug"       db:"slug"`
	Config    TenantConfig `json:"config"     db:"config"`
	Status    TenantStatus `json:"status"     db:"status"`
	CreatedAt time.Time    `json:"created_at" db:"created_at"`
	UpdatedAt time.Time    `json:"updated_at" db:"updated_at"`
}

// IsActive returns true if the tenant status is active.
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// TenantConfig holds per-tenant configuration stored as JSONB.
type TenantConfig struct {
	// PasswordPolicy overrides the global password policy for this tenant.
	// Nil fields fall back to the global default.
	PasswordPolicy *TenantPasswordPolicy `json:"password_policy,omitempty"`

	// MFA enforcement settings for this tenant.
	MFA *TenantMFAConfig `json:"mfa,omitempty"`

	// AllowedOAuthProviders restricts which OAuth providers users may link.
	// Empty slice means all globally-enabled providers are allowed.
	AllowedOAuthProviders []string `json:"allowed_oauth_providers,omitempty"`

	// TokenTTLs overrides default token time-to-live values (in seconds).
	TokenTTLs *TenantTokenTTLs `json:"token_ttls,omitempty"`
}

// TenantPasswordPolicy defines per-tenant password requirement overrides.
type TenantPasswordPolicy struct {
	MinLength    *int `json:"min_length,omitempty"`
	MaxLength    *int `json:"max_length,omitempty"`
	MaxAgeDays   *int `json:"max_age_days,omitempty"`
	HistoryCount *int `json:"history_count,omitempty"`
}

// TenantMFAConfig defines per-tenant MFA enforcement settings.
type TenantMFAConfig struct {
	// Required forces all users in this tenant to enrol MFA.
	Required bool `json:"required"`

	// AllowedMethods restricts which MFA methods are available.
	// Empty slice means all methods are allowed.
	AllowedMethods []string `json:"allowed_methods,omitempty"`

	// GracePeriodDays is the number of days after account creation
	// before MFA becomes mandatory (0 = immediate).
	GracePeriodDays int `json:"grace_period_days,omitempty"`
}

// TenantTokenTTLs defines per-tenant token lifetime overrides (in seconds).
type TenantTokenTTLs struct {
	AccessTokenTTL  *int `json:"access_token_ttl,omitempty"`
	RefreshTokenTTL *int `json:"refresh_token_ttl,omitempty"`
}
