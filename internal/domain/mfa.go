package domain

import (
	"time"

	"github.com/google/uuid"
)

// MFAMethod represents the type of MFA used.
type MFAMethod string

const (
	MFAMethodTOTP MFAMethod = "totp"
)

// MFASecret represents a stored MFA secret for a user.
type MFASecret struct {
	ID        uuid.UUID
	UserID    string
	Method    MFAMethod
	Secret    string
	Confirmed bool
	CreatedAt time.Time
	UpdatedAt time.Time
}

// MFABackupCode represents a single backup code for a user.
type MFABackupCode struct {
	ID        uuid.UUID
	UserID    string
	CodeHash  string
	UsedAt    *time.Time
	CreatedAt time.Time
}

// MFAStatus summarises whether MFA is enabled and which methods are confirmed.
type MFAStatus struct {
	Enabled          bool
	ConfirmedMethods []MFAMethod
	BackupCodesLeft  int
}
