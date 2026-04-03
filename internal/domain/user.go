package domain

import "time"

// User represents a user account in the system.
type User struct {
	ID           string
	Email        string
	PasswordHash string
	Name         string
	Roles        []string
	Locked       bool
	LockedAt     *time.Time
	LockedReason string
	LastLoginAt  *time.Time
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    *time.Time
}

// IsActive returns true if the user is not locked and not soft-deleted.
func (u *User) IsActive() bool {
	return !u.Locked && u.DeletedAt == nil
}

// RefreshTokenRecord represents a stored refresh token signature in the database.
type RefreshTokenRecord struct {
	Signature string
	UserID    string
	ExpiresAt time.Time
	CreatedAt time.Time
	RevokedAt *time.Time
}

// IsRevoked returns true if the token has been revoked.
func (r *RefreshTokenRecord) IsRevoked() bool {
	return r.RevokedAt != nil
}

// IsExpired returns true if the token has expired.
func (r *RefreshTokenRecord) IsExpired() bool {
	return time.Now().After(r.ExpiresAt)
}
