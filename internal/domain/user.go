package domain

import "time"

// User represents a user account in the system.
type User struct {
	ID                        string
	TenantID                  string
	Email                     string
	PasswordHash              string
	Name                      string
	Roles                     []string
	Locked                    bool
	LockedAt                  *time.Time
	LockedReason              string
	EmailVerified             bool
	EmailVerifyToken          *string
	EmailVerifyTokenExpiresAt *time.Time
	LastLoginAt               *time.Time
	ForcePasswordChange       bool
	PasswordChangedAt         *time.Time
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
	DeletedAt                 *time.Time
}

// IsActive returns true if the user is not locked and not soft-deleted.
func (u *User) IsActive() bool {
	return !u.Locked && u.DeletedAt == nil
}

// PasswordPolicy defines configurable password requirements.
type PasswordPolicy struct {
	MinLength    int // minimum password length (default: NistMinPasswordLength)
	MaxLength    int // maximum password length (0 = no limit)
	MaxAgeDays   int // password expiration in days (0 = never expires)
	HistoryCount int // number of previous passwords to check for reuse (0 = disabled)
}

// PasswordHistoryEntry represents a historical password hash for reuse detection.
type PasswordHistoryEntry struct {
	ID           string
	TenantID     string
	UserID       string
	PasswordHash string
	CreatedAt    time.Time
}

// RefreshTokenRecord represents a stored refresh token signature in the database.
type RefreshTokenRecord struct {
	Signature string
	TenantID  string
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
