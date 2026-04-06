package domain

import "time"

// PasswordPolicy defines tenant-scoped password policy configuration.
// The ID is either a tenant identifier or "default" for the global policy.
type PasswordPolicy struct {
	ID           string
	MinLength    int
	MaxLength    int
	MaxAgeDays   int // 0 = no expiry
	HistoryCount int // number of previous passwords to check against
	RequireMFA   bool
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

// PasswordHistoryEntry records a previously used password hash for a user.
type PasswordHistoryEntry struct {
	ID           string
	UserID       string
	PasswordHash string
	CreatedAt    time.Time
}
