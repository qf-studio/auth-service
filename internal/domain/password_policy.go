package domain

import "time"

// PasswordPolicy defines configurable password requirements for a tenant or global scope.
type PasswordPolicy struct {
	ID                  string
	Name                string
	MinLength           int
	MaxLength           int
	MaxAgeDays          int
	HistoryCount        int
	RequireMFA          bool
	IsDefault           bool
	CreatedAt           time.Time
	UpdatedAt           time.Time
	DeletedAt           *time.Time
}
