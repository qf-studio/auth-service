package domain

import "time"

// OAuthAccount represents a linked social-login identity for a user.
type OAuthAccount struct {
	ID             string    `json:"id"               db:"id"`
	UserID         string    `json:"user_id"          db:"user_id"`
	Provider       string    `json:"provider"         db:"provider"`
	ProviderUserID string    `json:"provider_user_id" db:"provider_user_id"`
	Email          string    `json:"email"            db:"email"`
	CreatedAt      time.Time `json:"created_at"       db:"created_at"`
}
