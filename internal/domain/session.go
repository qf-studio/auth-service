package domain

import "time"

// Session represents an active user session with device and location metadata.
type Session struct {
	ID                string    `json:"session_id"`
	UserID            string    `json:"user_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IP                string    `json:"ip"`
	UserAgent         string    `json:"user_agent"`
	RefreshTokenJTI   string    `json:"refresh_token_jti"`
	CreatedAt         time.Time `json:"created_at"`
	LastActivityAt    time.Time `json:"last_activity_at"`
}
