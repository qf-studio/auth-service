package domain

import "time"

// User status constants.
const (
	UserStatusActive    = "active"
	UserStatusLocked    = "locked"
	UserStatusSuspended = "suspended"
)

// User represents an authenticated user in the system.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Status       string
	Roles        []string
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
}
