package domain

import "time"

// RefreshToken represents a stored refresh token record.
// Only the signature portion of the token is stored, never the full token.
type RefreshToken struct {
	Signature string
	UserID    string
	ExpiresAt time.Time
	RevokedAt *time.Time
	CreatedAt time.Time
}

// IsRevoked reports whether this refresh token has been revoked.
func (t *RefreshToken) IsRevoked() bool {
	return t.RevokedAt != nil
}

// IsExpired reports whether this refresh token has expired.
func (t *RefreshToken) IsExpired() bool {
	return time.Now().After(t.ExpiresAt)
}
