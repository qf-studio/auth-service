package domain

import (
	"time"

	"github.com/google/uuid"
)

// MFASecret represents a user's MFA enrollment (e.g. TOTP secret).
type MFASecret struct {
	ID       string
	TenantID uuid.UUID
	UserID   string
	Type        string // "totp", "webauthn" (Phase 2)
	Secret      string // encrypted TOTP secret
	Confirmed   bool
	ConfirmedAt *time.Time
	CreatedAt   time.Time
	UpdatedAt   time.Time
	DeletedAt   *time.Time
}

// BackupCode represents a single hashed MFA backup code.
type BackupCode struct {
	ID       string
	TenantID uuid.UUID
	UserID   string
	CodeHash  string
	Used      bool
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MFAStatus summarises whether MFA is enabled for a user.
type MFAStatus struct {
	UserID     string
	Enabled    bool
	Type       string // active MFA type, empty if not enabled
	Confirmed  bool
	BackupLeft int // remaining unused backup codes
}
