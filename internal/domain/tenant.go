package domain

import "time"

// Tenant represents a tenant in the multi-tenant auth service.
type Tenant struct {
	ID        string     `json:"id"         db:"id"`
	Slug      string     `json:"slug"       db:"slug"`
	Name      string     `json:"name"       db:"name"`
	Active    bool       `json:"active"     db:"active"`
	CreatedAt time.Time  `json:"created_at" db:"created_at"`
	UpdatedAt time.Time  `json:"updated_at" db:"updated_at"`
	DeletedAt *time.Time `json:"deleted_at" db:"deleted_at"`
}

// IsActive returns true if the tenant is active and not soft-deleted.
func (t *Tenant) IsActive() bool {
	return t.Active && t.DeletedAt == nil
}
